rule TTP_XOR_WriteProcessMemory_ed17 {
  strings:
    $key_ed17 = { ba 65 [2] 88 47 [2] 8e 72 [2] a0 72 [2] 9f 6e }

  condition:
    any of them
}