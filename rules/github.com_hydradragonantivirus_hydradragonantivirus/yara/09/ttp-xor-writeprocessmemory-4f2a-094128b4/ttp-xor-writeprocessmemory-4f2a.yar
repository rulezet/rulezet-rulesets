rule TTP_XOR_WriteProcessMemory_4f2a {
  strings:
    $key_4f2a = { 18 58 [2] 2a 7a [2] 2c 4f [2] 02 4f [2] 3d 53 }

  condition:
    any of them
}