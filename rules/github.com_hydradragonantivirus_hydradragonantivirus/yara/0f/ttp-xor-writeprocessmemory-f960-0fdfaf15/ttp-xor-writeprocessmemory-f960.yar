rule TTP_XOR_WriteProcessMemory_f960 {
  strings:
    $key_f960 = { ae 12 [2] 9c 30 [2] 9a 05 [2] b4 05 [2] 8b 19 }

  condition:
    any of them
}