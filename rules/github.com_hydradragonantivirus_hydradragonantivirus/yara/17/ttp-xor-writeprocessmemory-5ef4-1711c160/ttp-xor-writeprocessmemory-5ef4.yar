rule TTP_XOR_WriteProcessMemory_5ef4 {
  strings:
    $key_5ef4 = { 09 86 [2] 3b a4 [2] 3d 91 [2] 13 91 [2] 2c 8d }

  condition:
    any of them
}