rule TTP_XOR_WriteProcessMemory_f461 {
  strings:
    $key_f461 = { a3 13 [2] 91 31 [2] 97 04 [2] b9 04 [2] 86 18 }

  condition:
    any of them
}