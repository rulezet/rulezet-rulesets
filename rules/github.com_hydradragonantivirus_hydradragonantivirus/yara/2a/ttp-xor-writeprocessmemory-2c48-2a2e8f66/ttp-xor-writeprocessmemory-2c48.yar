rule TTP_XOR_WriteProcessMemory_2c48 {
  strings:
    $key_2c48 = { 7b 3a [2] 49 18 [2] 4f 2d [2] 61 2d [2] 5e 31 }

  condition:
    any of them
}