rule TTP_XOR_WriteProcessMemory_6a4a {
  strings:
    $key_6a4a = { 3d 38 [2] 0f 1a [2] 09 2f [2] 27 2f [2] 18 33 }

  condition:
    any of them
}