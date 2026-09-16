rule TTP_XOR_WriteProcessMemory_2c78 {
  strings:
    $key_2c78 = { 7b 0a [2] 49 28 [2] 4f 1d [2] 61 1d [2] 5e 01 }

  condition:
    any of them
}