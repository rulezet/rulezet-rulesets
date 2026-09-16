rule TTP_XOR_WriteProcessMemory_2c6d {
  strings:
    $key_2c6d = { 7b 1f [2] 49 3d [2] 4f 08 [2] 61 08 [2] 5e 14 }

  condition:
    any of them
}