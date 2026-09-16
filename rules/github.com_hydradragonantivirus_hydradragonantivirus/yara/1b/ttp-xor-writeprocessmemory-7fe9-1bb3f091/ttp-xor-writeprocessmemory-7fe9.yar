rule TTP_XOR_WriteProcessMemory_7fe9 {
  strings:
    $key_7fe9 = { 28 9b [2] 1a b9 [2] 1c 8c [2] 32 8c [2] 0d 90 }

  condition:
    any of them
}