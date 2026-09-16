rule TTP_XOR_WriteProcessMemory_4ec2 {
  strings:
    $key_4ec2 = { 19 b0 [2] 2b 92 [2] 2d a7 [2] 03 a7 [2] 3c bb }

  condition:
    any of them
}