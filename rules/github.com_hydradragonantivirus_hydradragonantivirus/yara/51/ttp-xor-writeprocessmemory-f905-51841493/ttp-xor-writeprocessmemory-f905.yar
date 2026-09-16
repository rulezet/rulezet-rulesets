rule TTP_XOR_WriteProcessMemory_f905 {
  strings:
    $key_f905 = { ae 77 [2] 9c 55 [2] 9a 60 [2] b4 60 [2] 8b 7c }

  condition:
    any of them
}