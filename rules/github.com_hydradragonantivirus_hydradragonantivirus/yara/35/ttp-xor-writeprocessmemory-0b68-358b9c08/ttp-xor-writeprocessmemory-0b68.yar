rule TTP_XOR_WriteProcessMemory_0b68 {
  strings:
    $key_0b68 = { 5c 1a [2] 6e 38 [2] 68 0d [2] 46 0d [2] 79 11 }

  condition:
    any of them
}