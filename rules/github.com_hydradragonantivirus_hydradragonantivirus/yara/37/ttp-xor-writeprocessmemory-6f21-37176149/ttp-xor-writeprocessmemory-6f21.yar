rule TTP_XOR_WriteProcessMemory_6f21 {
  strings:
    $key_6f21 = { 38 53 [2] 0a 71 [2] 0c 44 [2] 22 44 [2] 1d 58 }

  condition:
    any of them
}