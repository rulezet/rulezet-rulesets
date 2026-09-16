rule TTP_XOR_WriteProcessMemory_2668 {
  strings:
    $key_2668 = { 71 1a [2] 43 38 [2] 45 0d [2] 6b 0d [2] 54 11 }

  condition:
    any of them
}