rule TTP_XOR_WriteProcessMemory_f292 {
  strings:
    $key_f292 = { a5 e0 [2] 97 c2 [2] 91 f7 [2] bf f7 [2] 80 eb }

  condition:
    any of them
}