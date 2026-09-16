rule TTP_XOR_WriteProcessMemory_f487 {
  strings:
    $key_f487 = { a3 f5 [2] 91 d7 [2] 97 e2 [2] b9 e2 [2] 86 fe }

  condition:
    any of them
}