rule TTP_XOR_WriteProcessMemory_3d5a {
  strings:
    $key_3d5a = { 6a 28 [2] 58 0a [2] 5e 3f [2] 70 3f [2] 4f 23 }

  condition:
    any of them
}