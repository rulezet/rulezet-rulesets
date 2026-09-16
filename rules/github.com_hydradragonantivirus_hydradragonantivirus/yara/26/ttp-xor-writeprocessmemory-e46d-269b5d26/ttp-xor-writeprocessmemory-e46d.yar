rule TTP_XOR_WriteProcessMemory_e46d {
  strings:
    $key_e46d = { b3 1f [2] 81 3d [2] 87 08 [2] a9 08 [2] 96 14 }

  condition:
    any of them
}