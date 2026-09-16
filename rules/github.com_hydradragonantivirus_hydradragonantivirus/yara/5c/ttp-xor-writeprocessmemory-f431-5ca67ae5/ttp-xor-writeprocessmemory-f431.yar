rule TTP_XOR_WriteProcessMemory_f431 {
  strings:
    $key_f431 = { a3 43 [2] 91 61 [2] 97 54 [2] b9 54 [2] 86 48 }

  condition:
    any of them
}