rule TTP_XOR_WriteProcessMemory_e887 {
  strings:
    $key_e887 = { bf f5 [2] 8d d7 [2] 8b e2 [2] a5 e2 [2] 9a fe }

  condition:
    any of them
}