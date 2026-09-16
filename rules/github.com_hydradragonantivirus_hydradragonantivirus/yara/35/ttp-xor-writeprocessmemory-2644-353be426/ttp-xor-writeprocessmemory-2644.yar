rule TTP_XOR_WriteProcessMemory_2644 {
  strings:
    $key_2644 = { 71 36 [2] 43 14 [2] 45 21 [2] 6b 21 [2] 54 3d }

  condition:
    any of them
}