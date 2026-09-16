rule TTP_XOR_WriteProcessMemory_ed47 {
  strings:
    $key_ed47 = { ba 35 [2] 88 17 [2] 8e 22 [2] a0 22 [2] 9f 3e }

  condition:
    any of them
}