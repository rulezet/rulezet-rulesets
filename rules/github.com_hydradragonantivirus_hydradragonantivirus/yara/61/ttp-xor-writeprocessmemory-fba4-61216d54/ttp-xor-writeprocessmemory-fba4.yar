rule TTP_XOR_WriteProcessMemory_fba4 {
  strings:
    $key_fba4 = { ac d6 [2] 9e f4 [2] 98 c1 [2] b6 c1 [2] 89 dd }

  condition:
    any of them
}