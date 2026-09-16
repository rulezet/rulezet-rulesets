rule TTP_XOR_WriteProcessMemory_5832 {
  strings:
    $key_5832 = { 0f 40 [2] 3d 62 [2] 3b 57 [2] 15 57 [2] 2a 4b }

  condition:
    any of them
}