rule TTP_XOR_WriteProcessMemory_4f4a {
  strings:
    $key_4f4a = { 18 38 [2] 2a 1a [2] 2c 2f [2] 02 2f [2] 3d 33 }

  condition:
    any of them
}