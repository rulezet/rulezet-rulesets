rule TTP_XOR_WriteProcessMemory_1ec2 {
  strings:
    $key_1ec2 = { 49 b0 [2] 7b 92 [2] 7d a7 [2] 53 a7 [2] 6c bb }

  condition:
    any of them
}