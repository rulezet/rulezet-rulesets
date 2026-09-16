rule TTP_XOR_WriteProcessMemory_1b44 {
  strings:
    $key_1b44 = { 4c 36 [2] 7e 14 [2] 78 21 [2] 56 21 [2] 69 3d }

  condition:
    any of them
}