rule TTP_XOR_WriteProcessMemory_3f30 {
  strings:
    $key_3f30 = { 68 42 [2] 5a 60 [2] 5c 55 [2] 72 55 [2] 4d 49 }

  condition:
    any of them
}