rule TTP_XOR_WriteProcessMemory_f912 {
  strings:
    $key_f912 = { ae 60 [2] 9c 42 [2] 9a 77 [2] b4 77 [2] 8b 6b }

  condition:
    any of them
}