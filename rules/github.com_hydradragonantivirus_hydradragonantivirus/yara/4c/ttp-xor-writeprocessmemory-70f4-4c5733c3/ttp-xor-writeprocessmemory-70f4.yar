rule TTP_XOR_WriteProcessMemory_70f4 {
  strings:
    $key_70f4 = { 27 86 [2] 15 a4 [2] 13 91 [2] 3d 91 [2] 02 8d }

  condition:
    any of them
}