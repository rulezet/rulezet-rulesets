rule TTP_XOR_WriteProcessMemory_3821 {
  strings:
    $key_3821 = { 6f 53 [2] 5d 71 [2] 5b 44 [2] 75 44 [2] 4a 58 }

  condition:
    any of them
}