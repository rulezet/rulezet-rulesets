rule TTP_XOR_WriteProcessMemory_f885 {
  strings:
    $key_f885 = { af f7 [2] 9d d5 [2] 9b e0 [2] b5 e0 [2] 8a fc }

  condition:
    any of them
}