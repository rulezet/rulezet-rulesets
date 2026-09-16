rule TTP_XOR_WriteProcessMemory_ed67 {
  strings:
    $key_ed67 = { ba 15 [2] 88 37 [2] 8e 02 [2] a0 02 [2] 9f 1e }

  condition:
    any of them
}