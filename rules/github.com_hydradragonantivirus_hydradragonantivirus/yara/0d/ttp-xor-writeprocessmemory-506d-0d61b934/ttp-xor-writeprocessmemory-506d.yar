rule TTP_XOR_WriteProcessMemory_506d {
  strings:
    $key_506d = { 07 1f [2] 35 3d [2] 33 08 [2] 1d 08 [2] 22 14 }

  condition:
    any of them
}