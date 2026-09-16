rule TTP_XOR_WriteProcessMemory_eba2 {
  strings:
    $key_eba2 = { bc d0 [2] 8e f2 [2] 88 c7 [2] a6 c7 [2] 99 db }

  condition:
    any of them
}