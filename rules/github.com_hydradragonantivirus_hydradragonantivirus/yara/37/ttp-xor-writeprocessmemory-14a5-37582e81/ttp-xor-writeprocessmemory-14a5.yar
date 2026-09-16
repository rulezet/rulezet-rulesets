rule TTP_XOR_WriteProcessMemory_14a5 {
  strings:
    $key_14a5 = { 43 d7 [2] 71 f5 [2] 77 c0 [2] 59 c0 [2] 66 dc }

  condition:
    any of them
}