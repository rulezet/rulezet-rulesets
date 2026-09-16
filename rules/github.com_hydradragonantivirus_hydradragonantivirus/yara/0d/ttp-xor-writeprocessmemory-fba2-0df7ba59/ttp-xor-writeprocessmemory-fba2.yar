rule TTP_XOR_WriteProcessMemory_fba2 {
  strings:
    $key_fba2 = { ac d0 [2] 9e f2 [2] 98 c7 [2] b6 c7 [2] 89 db }

  condition:
    any of them
}