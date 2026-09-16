rule TTP_XOR_WriteProcessMemory_43a2 {
  strings:
    $key_43a2 = { 14 d0 [2] 26 f2 [2] 20 c7 [2] 0e c7 [2] 31 db }

  condition:
    any of them
}