rule TTP_XOR_WriteProcessMemory_6a3a {
  strings:
    $key_6a3a = { 3d 48 [2] 0f 6a [2] 09 5f [2] 27 5f [2] 18 43 }

  condition:
    any of them
}