rule TTP_XOR_WriteProcessMemory_f492 {
  strings:
    $key_f492 = { a3 e0 [2] 91 c2 [2] 97 f7 [2] b9 f7 [2] 86 eb }

  condition:
    any of them
}