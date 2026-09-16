rule TTP_XOR_WriteProcessMemory_f965 {
  strings:
    $key_f965 = { ae 17 [2] 9c 35 [2] 9a 00 [2] b4 00 [2] 8b 1c }

  condition:
    any of them
}