rule TTP_XOR_WriteProcessMemory_f950 {
  strings:
    $key_f950 = { ae 22 [2] 9c 00 [2] 9a 35 [2] b4 35 [2] 8b 29 }

  condition:
    any of them
}