rule TTP_XOR_WriteProcessMemory_14c7 {
  strings:
    $key_14c7 = { 43 b5 [2] 71 97 [2] 77 a2 [2] 59 a2 [2] 66 be }

  condition:
    any of them
}