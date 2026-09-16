rule TTP_XOR_WriteProcessMemory_2ec2 {
  strings:
    $key_2ec2 = { 79 b0 [2] 4b 92 [2] 4d a7 [2] 63 a7 [2] 5c bb }

  condition:
    any of them
}