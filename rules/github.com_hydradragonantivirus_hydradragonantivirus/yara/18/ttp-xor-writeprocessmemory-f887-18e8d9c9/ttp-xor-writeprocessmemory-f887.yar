rule TTP_XOR_WriteProcessMemory_f887 {
  strings:
    $key_f887 = { af f5 [2] 9d d7 [2] 9b e2 [2] b5 e2 [2] 8a fe }

  condition:
    any of them
}