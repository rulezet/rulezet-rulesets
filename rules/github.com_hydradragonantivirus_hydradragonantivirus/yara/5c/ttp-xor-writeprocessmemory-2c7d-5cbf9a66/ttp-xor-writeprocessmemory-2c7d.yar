rule TTP_XOR_WriteProcessMemory_2c7d {
  strings:
    $key_2c7d = { 7b 0f [2] 49 2d [2] 4f 18 [2] 61 18 [2] 5e 04 }

  condition:
    any of them
}