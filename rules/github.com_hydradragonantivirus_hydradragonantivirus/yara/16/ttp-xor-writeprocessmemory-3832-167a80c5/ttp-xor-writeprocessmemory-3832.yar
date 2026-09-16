rule TTP_XOR_WriteProcessMemory_3832 {
  strings:
    $key_3832 = { 6f 40 [2] 5d 62 [2] 5b 57 [2] 75 57 [2] 4a 4b }

  condition:
    any of them
}