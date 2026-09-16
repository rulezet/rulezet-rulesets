rule TTP_XOR_WriteProcessMemory_5e5a {
  strings:
    $key_5e5a = { 09 28 [2] 3b 0a [2] 3d 3f [2] 13 3f [2] 2c 23 }

  condition:
    any of them
}