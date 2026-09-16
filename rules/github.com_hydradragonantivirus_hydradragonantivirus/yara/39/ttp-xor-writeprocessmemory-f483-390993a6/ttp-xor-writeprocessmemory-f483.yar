rule TTP_XOR_WriteProcessMemory_f483 {
  strings:
    $key_f483 = { a3 f1 [2] 91 d3 [2] 97 e6 [2] b9 e6 [2] 86 fa }

  condition:
    any of them
}