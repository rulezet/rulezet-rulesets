rule TTP_XOR_WriteProcessMemory_3f26 {
  strings:
    $key_3f26 = { 68 54 [2] 5a 76 [2] 5c 43 [2] 72 43 [2] 4d 5f }

  condition:
    any of them
}