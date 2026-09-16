rule TTP_XOR_WriteProcessMemory_8722 {
  strings:
    $key_8722 = { d0 50 [2] e2 72 [2] e4 47 [2] ca 47 [2] f5 5b }

  condition:
    any of them
}