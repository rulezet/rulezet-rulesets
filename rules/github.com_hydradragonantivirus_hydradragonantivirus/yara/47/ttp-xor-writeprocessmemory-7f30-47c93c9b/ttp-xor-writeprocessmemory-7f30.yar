rule TTP_XOR_WriteProcessMemory_7f30 {
  strings:
    $key_7f30 = { 28 42 [2] 1a 60 [2] 1c 55 [2] 32 55 [2] 0d 49 }

  condition:
    any of them
}