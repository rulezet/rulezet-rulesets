rule TTP_XOR_WriteProcessMemory_7ec2 {
  strings:
    $key_7ec2 = { 29 b0 [2] 1b 92 [2] 1d a7 [2] 33 a7 [2] 0c bb }

  condition:
    any of them
}