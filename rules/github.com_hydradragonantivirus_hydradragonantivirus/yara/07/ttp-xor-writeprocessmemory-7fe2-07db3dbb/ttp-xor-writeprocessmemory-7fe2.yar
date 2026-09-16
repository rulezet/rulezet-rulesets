rule TTP_XOR_WriteProcessMemory_7fe2 {
  strings:
    $key_7fe2 = { 28 90 [2] 1a b2 [2] 1c 87 [2] 32 87 [2] 0d 9b }

  condition:
    any of them
}