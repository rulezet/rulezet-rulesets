rule TTP_XOR_WriteProcessMemory_f421 {
  strings:
    $key_f421 = { a3 53 [2] 91 71 [2] 97 44 [2] b9 44 [2] 86 58 }

  condition:
    any of them
}