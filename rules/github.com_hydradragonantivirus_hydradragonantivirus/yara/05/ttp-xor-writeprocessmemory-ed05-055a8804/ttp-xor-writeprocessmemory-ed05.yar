rule TTP_XOR_WriteProcessMemory_ed05 {
  strings:
    $key_ed05 = { ba 77 [2] 88 55 [2] 8e 60 [2] a0 60 [2] 9f 7c }

  condition:
    any of them
}