rule TTP_XOR_WriteProcessMemory_7065 {
  strings:
    $key_7065 = { 27 17 [2] 15 35 [2] 13 00 [2] 3d 00 [2] 02 1c }

  condition:
    any of them
}