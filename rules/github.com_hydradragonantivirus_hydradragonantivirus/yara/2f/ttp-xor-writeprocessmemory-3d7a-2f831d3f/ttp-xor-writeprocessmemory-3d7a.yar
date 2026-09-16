rule TTP_XOR_WriteProcessMemory_3d7a {
  strings:
    $key_3d7a = { 6a 08 [2] 58 2a [2] 5e 1f [2] 70 1f [2] 4f 03 }

  condition:
    any of them
}