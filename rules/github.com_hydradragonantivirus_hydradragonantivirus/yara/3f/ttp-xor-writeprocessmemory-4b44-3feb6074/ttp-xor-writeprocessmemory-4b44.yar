rule TTP_XOR_WriteProcessMemory_4b44 {
  strings:
    $key_4b44 = { 1c 36 [2] 2e 14 [2] 28 21 [2] 06 21 [2] 39 3d }

  condition:
    any of them
}