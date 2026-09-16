rule TTP_XOR_WriteProcessMemory_0f30 {
  strings:
    $key_0f30 = { 58 42 [2] 6a 60 [2] 6c 55 [2] 42 55 [2] 7d 49 }

  condition:
    any of them
}