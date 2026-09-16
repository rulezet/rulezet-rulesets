rule TTP_XOR_WriteProcessMemory_2bb1 {
  strings:
    $key_2bb1 = { 7c c3 [2] 4e e1 [2] 48 d4 [2] 66 d4 [2] 59 c8 }

  condition:
    any of them
}