rule TTP_XOR_WriteProcessMemory_6d44 {
  strings:
    $key_6d44 = { 3a 36 [2] 08 14 [2] 0e 21 [2] 20 21 [2] 1f 3d }

  condition:
    any of them
}