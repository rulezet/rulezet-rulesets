rule TTP_XOR_WriteProcessMemory_6a5d {
  strings:
    $key_6a5d = { 3d 2f [2] 0f 0d [2] 09 38 [2] 27 38 [2] 18 24 }

  condition:
    any of them
}