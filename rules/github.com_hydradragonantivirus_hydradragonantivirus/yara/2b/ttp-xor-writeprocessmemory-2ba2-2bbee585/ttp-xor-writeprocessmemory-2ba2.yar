rule TTP_XOR_WriteProcessMemory_2ba2 {
  strings:
    $key_2ba2 = { 7c d0 [2] 4e f2 [2] 48 c7 [2] 66 c7 [2] 59 db }

  condition:
    any of them
}