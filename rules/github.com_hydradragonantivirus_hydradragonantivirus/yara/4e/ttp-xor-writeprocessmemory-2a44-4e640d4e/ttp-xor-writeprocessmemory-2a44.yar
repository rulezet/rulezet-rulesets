rule TTP_XOR_WriteProcessMemory_2a44 {
  strings:
    $key_2a44 = { 7d 36 [2] 4f 14 [2] 49 21 [2] 67 21 [2] 58 3d }

  condition:
    any of them
}