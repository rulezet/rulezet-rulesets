rule TTP_XOR_WriteProcessMemory_3b68 {
  strings:
    $key_3b68 = { 6c 1a [2] 5e 38 [2] 58 0d [2] 76 0d [2] 49 11 }

  condition:
    any of them
}