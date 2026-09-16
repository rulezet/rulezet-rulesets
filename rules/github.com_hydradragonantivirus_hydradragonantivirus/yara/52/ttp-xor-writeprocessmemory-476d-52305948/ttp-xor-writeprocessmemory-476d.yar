rule TTP_XOR_WriteProcessMemory_476d {
  strings:
    $key_476d = { 10 1f [2] 22 3d [2] 24 08 [2] 0a 08 [2] 35 14 }

  condition:
    any of them
}