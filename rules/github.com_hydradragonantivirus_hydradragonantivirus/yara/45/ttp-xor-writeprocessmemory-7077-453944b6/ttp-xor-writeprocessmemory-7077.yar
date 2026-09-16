rule TTP_XOR_WriteProcessMemory_7077 {
  strings:
    $key_7077 = { 27 05 [2] 15 27 [2] 13 12 [2] 3d 12 [2] 02 0e }

  condition:
    any of them
}