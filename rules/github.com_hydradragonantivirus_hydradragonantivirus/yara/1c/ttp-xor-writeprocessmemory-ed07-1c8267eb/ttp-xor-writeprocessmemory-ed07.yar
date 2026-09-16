rule TTP_XOR_WriteProcessMemory_ed07 {
  strings:
    $key_ed07 = { ba 75 [2] 88 57 [2] 8e 62 [2] a0 62 [2] 9f 7e }

  condition:
    any of them
}