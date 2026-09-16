rule TTP_XOR_WriteProcessMemory_2f68 {
  strings:
    $key_2f68 = { 78 1a [2] 4a 38 [2] 4c 0d [2] 62 0d [2] 5d 11 }

  condition:
    any of them
}