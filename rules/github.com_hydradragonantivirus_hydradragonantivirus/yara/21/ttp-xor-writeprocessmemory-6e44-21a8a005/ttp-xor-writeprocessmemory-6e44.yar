rule TTP_XOR_WriteProcessMemory_6e44 {
  strings:
    $key_6e44 = { 39 36 [2] 0b 14 [2] 0d 21 [2] 23 21 [2] 1c 3d }

  condition:
    any of them
}