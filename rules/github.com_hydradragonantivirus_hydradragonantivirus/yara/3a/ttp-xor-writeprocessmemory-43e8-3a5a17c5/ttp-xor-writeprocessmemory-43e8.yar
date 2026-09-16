rule TTP_XOR_WriteProcessMemory_43e8 {
  strings:
    $key_43e8 = { 14 9a [2] 26 b8 [2] 20 8d [2] 0e 8d [2] 31 91 }

  condition:
    any of them
}