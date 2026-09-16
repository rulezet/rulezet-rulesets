rule TTP_XOR_WriteProcessMemory_0e44 {
  strings:
    $key_0e44 = { 59 36 [2] 6b 14 [2] 6d 21 [2] 43 21 [2] 7c 3d }

  condition:
    any of them
}