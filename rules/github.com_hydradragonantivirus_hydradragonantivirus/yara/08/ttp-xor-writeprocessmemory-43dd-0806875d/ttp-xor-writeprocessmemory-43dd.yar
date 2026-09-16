rule TTP_XOR_WriteProcessMemory_43dd {
  strings:
    $key_43dd = { 14 af [2] 26 8d [2] 20 b8 [2] 0e b8 [2] 31 a4 }

  condition:
    any of them
}