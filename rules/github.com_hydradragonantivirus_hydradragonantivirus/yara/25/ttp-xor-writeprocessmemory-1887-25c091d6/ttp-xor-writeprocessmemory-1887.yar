rule TTP_XOR_WriteProcessMemory_1887 {
  strings:
    $key_1887 = { 4f f5 [2] 7d d7 [2] 7b e2 [2] 55 e2 [2] 6a fe }

  condition:
    any of them
}