rule TTP_XOR_WriteProcessMemory_5864 {
  strings:
    $key_5864 = { 0f 16 [2] 3d 34 [2] 3b 01 [2] 15 01 [2] 2a 1d }

  condition:
    any of them
}