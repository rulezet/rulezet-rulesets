rule TTP_XOR_WriteProcessMemory_5a6d {
  strings:
    $key_5a6d = { 0d 1f [2] 3f 3d [2] 39 08 [2] 17 08 [2] 28 14 }

  condition:
    any of them
}