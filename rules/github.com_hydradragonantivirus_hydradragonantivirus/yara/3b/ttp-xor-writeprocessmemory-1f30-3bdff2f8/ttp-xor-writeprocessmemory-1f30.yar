rule TTP_XOR_WriteProcessMemory_1f30 {
  strings:
    $key_1f30 = { 48 42 [2] 7a 60 [2] 7c 55 [2] 52 55 [2] 6d 49 }

  condition:
    any of them
}