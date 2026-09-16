rule TTP_XOR_WriteProcessMemory_ed55 {
  strings:
    $key_ed55 = { ba 27 [2] 88 05 [2] 8e 30 [2] a0 30 [2] 9f 2c }

  condition:
    any of them
}