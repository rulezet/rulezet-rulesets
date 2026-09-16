rule TTP_XOR_WriteProcessMemory_1644 {
  strings:
    $key_1644 = { 41 36 [2] 73 14 [2] 75 21 [2] 5b 21 [2] 64 3d }

  condition:
    any of them
}