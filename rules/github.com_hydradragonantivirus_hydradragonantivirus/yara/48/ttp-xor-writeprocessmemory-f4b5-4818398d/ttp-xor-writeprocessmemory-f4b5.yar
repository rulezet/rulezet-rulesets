rule TTP_XOR_WriteProcessMemory_f4b5 {
  strings:
    $key_f4b5 = { a3 c7 [2] 91 e5 [2] 97 d0 [2] b9 d0 [2] 86 cc }

  condition:
    any of them
}