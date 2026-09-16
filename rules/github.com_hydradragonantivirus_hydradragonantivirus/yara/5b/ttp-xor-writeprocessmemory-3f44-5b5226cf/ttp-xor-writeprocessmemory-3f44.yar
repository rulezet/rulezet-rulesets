rule TTP_XOR_WriteProcessMemory_3f44 {
  strings:
    $key_3f44 = { 68 36 [2] 5a 14 [2] 5c 21 [2] 72 21 [2] 4d 3d }

  condition:
    any of them
}