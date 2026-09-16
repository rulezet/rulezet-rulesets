rule TTP_XOR_WriteProcessMemory_7144 {
  strings:
    $key_7144 = { 26 36 [2] 14 14 [2] 12 21 [2] 3c 21 [2] 03 3d }

  condition:
    any of them
}