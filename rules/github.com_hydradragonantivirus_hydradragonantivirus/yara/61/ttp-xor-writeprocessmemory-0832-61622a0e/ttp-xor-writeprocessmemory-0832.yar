rule TTP_XOR_WriteProcessMemory_0832 {
  strings:
    $key_0832 = { 5f 40 [2] 6d 62 [2] 6b 57 [2] 45 57 [2] 7a 4b }

  condition:
    any of them
}