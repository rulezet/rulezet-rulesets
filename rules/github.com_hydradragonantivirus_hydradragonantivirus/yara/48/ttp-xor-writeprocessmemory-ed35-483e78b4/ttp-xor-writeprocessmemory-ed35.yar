rule TTP_XOR_WriteProcessMemory_ed35 {
  strings:
    $key_ed35 = { ba 47 [2] 88 65 [2] 8e 50 [2] a0 50 [2] 9f 4c }

  condition:
    any of them
}