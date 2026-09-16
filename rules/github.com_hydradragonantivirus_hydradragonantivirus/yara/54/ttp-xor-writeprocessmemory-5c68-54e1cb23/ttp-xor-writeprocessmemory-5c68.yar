rule TTP_XOR_WriteProcessMemory_5c68 {
  strings:
    $key_5c68 = { 0b 1a [2] 39 38 [2] 3f 0d [2] 11 0d [2] 2e 11 }

  condition:
    any of them
}