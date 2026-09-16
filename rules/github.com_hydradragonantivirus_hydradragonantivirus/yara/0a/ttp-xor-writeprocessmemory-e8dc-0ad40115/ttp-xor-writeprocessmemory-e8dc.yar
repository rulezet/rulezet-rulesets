rule TTP_XOR_WriteProcessMemory_e8dc {
  strings:
    $key_e8dc = { bf ae [2] 8d 8c [2] 8b b9 [2] a5 b9 [2] 9a a5 }

  condition:
    any of them
}