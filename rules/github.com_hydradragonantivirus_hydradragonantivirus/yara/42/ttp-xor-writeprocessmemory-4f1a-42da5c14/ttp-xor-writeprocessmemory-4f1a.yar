rule TTP_XOR_WriteProcessMemory_4f1a {
  strings:
    $key_4f1a = { 18 68 [2] 2a 4a [2] 2c 7f [2] 02 7f [2] 3d 63 }

  condition:
    any of them
}