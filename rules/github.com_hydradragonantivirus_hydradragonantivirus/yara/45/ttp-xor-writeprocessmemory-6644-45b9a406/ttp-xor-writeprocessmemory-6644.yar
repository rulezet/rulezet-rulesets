rule TTP_XOR_WriteProcessMemory_6644 {
  strings:
    $key_6644 = { 31 36 [2] 03 14 [2] 05 21 [2] 2b 21 [2] 14 3d }

  condition:
    any of them
}