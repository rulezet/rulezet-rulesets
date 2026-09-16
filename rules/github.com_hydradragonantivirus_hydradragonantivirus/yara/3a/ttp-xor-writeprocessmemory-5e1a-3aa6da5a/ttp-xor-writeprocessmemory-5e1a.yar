rule TTP_XOR_WriteProcessMemory_5e1a {
  strings:
    $key_5e1a = { 09 68 [2] 3b 4a [2] 3d 7f [2] 13 7f [2] 2c 63 }

  condition:
    any of them
}