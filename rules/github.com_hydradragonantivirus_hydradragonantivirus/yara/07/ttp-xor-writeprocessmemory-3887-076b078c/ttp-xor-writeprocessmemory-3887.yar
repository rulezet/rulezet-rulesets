rule TTP_XOR_WriteProcessMemory_3887 {
  strings:
    $key_3887 = { 6f f5 [2] 5d d7 [2] 5b e2 [2] 75 e2 [2] 4a fe }

  condition:
    any of them
}