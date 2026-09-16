rule TTP_XOR_WriteProcessMemory_14a4 {
  strings:
    $key_14a4 = { 43 d6 [2] 71 f4 [2] 77 c1 [2] 59 c1 [2] 66 dd }

  condition:
    any of them
}