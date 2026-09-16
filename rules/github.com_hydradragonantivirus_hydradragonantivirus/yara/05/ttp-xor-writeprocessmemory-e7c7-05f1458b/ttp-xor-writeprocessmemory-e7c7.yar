rule TTP_XOR_WriteProcessMemory_e7c7 {
  strings:
    $key_e7c7 = { b0 b5 [2] 82 97 [2] 84 a2 [2] aa a2 [2] 95 be }

  condition:
    any of them
}