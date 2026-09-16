rule TTP_XOR_WriteProcessMemory_14b5 {
  strings:
    $key_14b5 = { 43 c7 [2] 71 e5 [2] 77 d0 [2] 59 d0 [2] 66 cc }

  condition:
    any of them
}