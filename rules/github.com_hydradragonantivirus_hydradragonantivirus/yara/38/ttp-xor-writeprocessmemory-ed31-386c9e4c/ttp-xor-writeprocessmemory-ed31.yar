rule TTP_XOR_WriteProcessMemory_ed31 {
  strings:
    $key_ed31 = { ba 43 [2] 88 61 [2] 8e 54 [2] a0 54 [2] 9f 48 }

  condition:
    any of them
}