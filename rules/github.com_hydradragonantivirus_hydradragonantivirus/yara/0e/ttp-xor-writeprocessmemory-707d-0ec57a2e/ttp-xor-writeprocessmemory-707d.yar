rule TTP_XOR_WriteProcessMemory_707d {
  strings:
    $key_707d = { 27 0f [2] 15 2d [2] 13 18 [2] 3d 18 [2] 02 04 }

  condition:
    any of them
}