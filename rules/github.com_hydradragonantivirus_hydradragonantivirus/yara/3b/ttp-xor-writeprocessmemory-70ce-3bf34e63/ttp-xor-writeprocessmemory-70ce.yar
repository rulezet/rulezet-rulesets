rule TTP_XOR_WriteProcessMemory_70ce {
  strings:
    $key_70ce = { 27 bc [2] 15 9e [2] 13 ab [2] 3d ab [2] 02 b7 }

  condition:
    any of them
}