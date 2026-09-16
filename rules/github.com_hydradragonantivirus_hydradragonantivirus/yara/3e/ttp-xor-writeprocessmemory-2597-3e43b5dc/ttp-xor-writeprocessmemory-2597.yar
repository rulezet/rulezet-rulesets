rule TTP_XOR_WriteProcessMemory_2597 {
  strings:
    $key_2597 = { 72 e5 [2] 40 c7 [2] 46 f2 [2] 68 f2 [2] 57 ee }

  condition:
    any of them
}