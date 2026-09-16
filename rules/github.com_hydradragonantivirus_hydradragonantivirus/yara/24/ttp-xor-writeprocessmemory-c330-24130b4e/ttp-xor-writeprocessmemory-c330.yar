rule TTP_XOR_WriteProcessMemory_c330 {
  strings:
    $key_c330 = { 94 42 [2] a6 60 [2] a0 55 [2] 8e 55 [2] b1 49 }

  condition:
    any of them
}