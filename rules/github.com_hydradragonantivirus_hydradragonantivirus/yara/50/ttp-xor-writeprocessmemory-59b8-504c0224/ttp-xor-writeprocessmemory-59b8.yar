rule TTP_XOR_WriteProcessMemory_59b8 {
  strings:
    $key_59b8 = { 0e ca [2] 3c e8 [2] 3a dd [2] 14 dd [2] 2b c1 }

  condition:
    any of them
}