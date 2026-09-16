rule TTP_XOR_WriteProcessMemory_fba3 {
  strings:
    $key_fba3 = { ac d1 [2] 9e f3 [2] 98 c6 [2] b6 c6 [2] 89 da }

  condition:
    any of them
}