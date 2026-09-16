rule TTP_XOR_WriteProcessMemory_3ec2 {
  strings:
    $key_3ec2 = { 69 b0 [2] 5b 92 [2] 5d a7 [2] 73 a7 [2] 4c bb }

  condition:
    any of them
}