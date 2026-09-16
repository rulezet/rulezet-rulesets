rule TTP_XOR_WriteProcessMemory_1b68 {
  strings:
    $key_1b68 = { 4c 1a [2] 7e 38 [2] 78 0d [2] 56 0d [2] 69 11 }

  condition:
    any of them
}