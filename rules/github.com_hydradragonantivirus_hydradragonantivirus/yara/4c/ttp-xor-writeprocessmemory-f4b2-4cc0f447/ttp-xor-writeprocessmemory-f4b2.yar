rule TTP_XOR_WriteProcessMemory_f4b2 {
  strings:
    $key_f4b2 = { a3 c0 [2] 91 e2 [2] 97 d7 [2] b9 d7 [2] 86 cb }

  condition:
    any of them
}