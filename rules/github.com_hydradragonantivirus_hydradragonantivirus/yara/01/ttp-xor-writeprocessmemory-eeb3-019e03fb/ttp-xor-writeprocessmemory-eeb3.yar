rule TTP_XOR_WriteProcessMemory_eeb3 {
  strings:
    $key_eeb3 = { b9 c1 [2] 8b e3 [2] 8d d6 [2] a3 d6 [2] 9c ca }

  condition:
    any of them
}