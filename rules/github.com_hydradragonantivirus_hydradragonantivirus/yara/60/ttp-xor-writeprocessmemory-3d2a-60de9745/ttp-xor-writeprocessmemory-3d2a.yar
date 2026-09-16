rule TTP_XOR_WriteProcessMemory_3d2a {
  strings:
    $key_3d2a = { 6a 58 [2] 58 7a [2] 5e 4f [2] 70 4f [2] 4f 53 }

  condition:
    any of them
}