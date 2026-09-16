rule TTP_XOR_WriteProcessMemory_2c68 {
  strings:
    $key_2c68 = { 7b 1a [2] 49 38 [2] 4f 0d [2] 61 0d [2] 5e 11 }

  condition:
    any of them
}