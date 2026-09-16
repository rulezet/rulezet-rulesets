rule TTP_XOR_WriteProcessMemory_4887 {
  strings:
    $key_4887 = { 1f f5 [2] 2d d7 [2] 2b e2 [2] 05 e2 [2] 3a fe }

  condition:
    any of them
}