rule TTP_XOR_WriteProcessMemory_7887 {
  strings:
    $key_7887 = { 2f f5 [2] 1d d7 [2] 1b e2 [2] 35 e2 [2] 0a fe }

  condition:
    any of them
}