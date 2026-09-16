rule TTP_XOR_WriteProcessMemory_43a3 {
  strings:
    $key_43a3 = { 14 d1 [2] 26 f3 [2] 20 c6 [2] 0e c6 [2] 31 da }

  condition:
    any of them
}