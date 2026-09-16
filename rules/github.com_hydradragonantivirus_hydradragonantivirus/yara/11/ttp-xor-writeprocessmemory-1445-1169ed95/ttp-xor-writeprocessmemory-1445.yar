rule TTP_XOR_WriteProcessMemory_1445 {
  strings:
    $key_1445 = { 43 37 [2] 71 15 [2] 77 20 [2] 59 20 [2] 66 3c }

  condition:
    any of them
}