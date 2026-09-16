rule TTP_XOR_WriteProcessMemory_f880 {
  strings:
    $key_f880 = { af f2 [2] 9d d0 [2] 9b e5 [2] b5 e5 [2] 8a f9 }

  condition:
    any of them
}