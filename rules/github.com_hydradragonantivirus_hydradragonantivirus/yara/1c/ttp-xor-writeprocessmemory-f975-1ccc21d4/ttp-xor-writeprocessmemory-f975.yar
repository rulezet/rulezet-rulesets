rule TTP_XOR_WriteProcessMemory_f975 {
  strings:
    $key_f975 = { ae 07 [2] 9c 25 [2] 9a 10 [2] b4 10 [2] 8b 0c }

  condition:
    any of them
}