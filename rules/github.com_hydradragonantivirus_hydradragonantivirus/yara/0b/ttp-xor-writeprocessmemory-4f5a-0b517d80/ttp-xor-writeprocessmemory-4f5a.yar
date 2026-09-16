rule TTP_XOR_WriteProcessMemory_4f5a {
  strings:
    $key_4f5a = { 18 28 [2] 2a 0a [2] 2c 3f [2] 02 3f [2] 3d 23 }

  condition:
    any of them
}