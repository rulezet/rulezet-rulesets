rule TTP_XOR_WriteProcessMemory_7fe6 {
  strings:
    $key_7fe6 = { 28 94 [2] 1a b6 [2] 1c 83 [2] 32 83 [2] 0d 9f }

  condition:
    any of them
}