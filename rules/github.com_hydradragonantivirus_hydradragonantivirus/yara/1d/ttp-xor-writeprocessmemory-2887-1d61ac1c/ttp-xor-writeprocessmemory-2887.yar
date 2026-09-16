rule TTP_XOR_WriteProcessMemory_2887 {
  strings:
    $key_2887 = { 7f f5 [2] 4d d7 [2] 4b e2 [2] 65 e2 [2] 5a fe }

  condition:
    any of them
}