rule TTP_XOR_WriteProcessMemory_3682 {
  strings:
    $key_3682 = { 61 f0 [2] 53 d2 [2] 55 e7 [2] 7b e7 [2] 44 fb }

  condition:
    any of them
}