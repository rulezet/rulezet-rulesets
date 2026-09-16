rule TTP_XOR_WriteProcessMemory_f4a3 {
  strings:
    $key_f4a3 = { a3 d1 [2] 91 f3 [2] 97 c6 [2] b9 c6 [2] 86 da }

  condition:
    any of them
}