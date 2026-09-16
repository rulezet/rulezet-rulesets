rule TTP_XOR_WriteProcessMemory_7053 {
  strings:
    $key_7053 = { 27 21 [2] 15 03 [2] 13 36 [2] 3d 36 [2] 02 2a }

  condition:
    any of them
}