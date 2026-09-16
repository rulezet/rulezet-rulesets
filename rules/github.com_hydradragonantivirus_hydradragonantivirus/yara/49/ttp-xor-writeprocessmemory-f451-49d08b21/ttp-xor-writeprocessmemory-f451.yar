rule TTP_XOR_WriteProcessMemory_f451 {
  strings:
    $key_f451 = { a3 23 [2] 91 01 [2] 97 34 [2] b9 34 [2] 86 28 }

  condition:
    any of them
}