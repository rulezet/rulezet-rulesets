rule TTP_XOR_WriteProcessMemory_5842 {
  strings:
    $key_5842 = { 0f 30 [2] 3d 12 [2] 3b 27 [2] 15 27 [2] 2a 3b }

  condition:
    any of them
}