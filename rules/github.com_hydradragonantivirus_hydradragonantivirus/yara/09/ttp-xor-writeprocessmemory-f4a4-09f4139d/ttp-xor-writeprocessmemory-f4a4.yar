rule TTP_XOR_WriteProcessMemory_f4a4 {
  strings:
    $key_f4a4 = { a3 d6 [2] 91 f4 [2] 97 c1 [2] b9 c1 [2] 86 dd }

  condition:
    any of them
}