rule TTP_XOR_WriteProcessMemory_7d44 {
  strings:
    $key_7d44 = { 2a 36 [2] 18 14 [2] 1e 21 [2] 30 21 [2] 0f 3d }

  condition:
    any of them
}