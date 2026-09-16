rule TTP_XOR_WriteProcessMemory_0a63 {
  strings:
    $key_0a63 = { 5d 11 [2] 6f 33 [2] 69 06 [2] 47 06 [2] 78 1a }

  condition:
    any of them
}