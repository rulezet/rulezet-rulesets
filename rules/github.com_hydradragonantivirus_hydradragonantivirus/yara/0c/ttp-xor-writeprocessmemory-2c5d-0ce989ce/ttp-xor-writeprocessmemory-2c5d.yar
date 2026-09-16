rule TTP_XOR_WriteProcessMemory_2c5d {
  strings:
    $key_2c5d = { 7b 2f [2] 49 0d [2] 4f 38 [2] 61 38 [2] 5e 24 }

  condition:
    any of them
}