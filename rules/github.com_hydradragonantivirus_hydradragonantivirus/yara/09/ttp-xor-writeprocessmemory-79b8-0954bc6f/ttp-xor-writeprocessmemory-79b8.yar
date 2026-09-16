rule TTP_XOR_WriteProcessMemory_79b8 {
  strings:
    $key_79b8 = { 2e ca [2] 1c e8 [2] 1a dd [2] 34 dd [2] 0b c1 }

  condition:
    any of them
}