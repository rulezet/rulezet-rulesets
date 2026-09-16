rule TTP_XOR_WriteProcessMemory_6a0d {
  strings:
    $key_6a0d = { 3d 7f [2] 0f 5d [2] 09 68 [2] 27 68 [2] 18 74 }

  condition:
    any of them
}