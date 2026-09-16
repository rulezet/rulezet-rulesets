rule TTP_XOR_WriteProcessMemory_5e7a {
  strings:
    $key_5e7a = { 09 08 [2] 3b 2a [2] 3d 1f [2] 13 1f [2] 2c 03 }

  condition:
    any of them
}