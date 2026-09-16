rule TTP_XOR_WriteProcessMemory_1b6d {
  strings:
    $key_1b6d = { 4c 1f [2] 7e 3d [2] 78 08 [2] 56 08 [2] 69 14 }

  condition:
    any of them
}