rule TTP_XOR_WriteProcessMemory_7f44 {
  strings:
    $key_7f44 = { 28 36 [2] 1a 14 [2] 1c 21 [2] 32 21 [2] 0d 3d }

  condition:
    any of them
}