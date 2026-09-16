rule TTP_XOR_WriteProcessMemory_526d {
  strings:
    $key_526d = { 05 1f [2] 37 3d [2] 31 08 [2] 1f 08 [2] 20 14 }

  condition:
    any of them
}