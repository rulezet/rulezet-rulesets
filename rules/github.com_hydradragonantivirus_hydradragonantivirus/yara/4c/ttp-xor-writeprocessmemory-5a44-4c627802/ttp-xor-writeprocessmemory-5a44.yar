rule TTP_XOR_WriteProcessMemory_5a44 {
  strings:
    $key_5a44 = { 0d 36 [2] 3f 14 [2] 39 21 [2] 17 21 [2] 28 3d }

  condition:
    any of them
}