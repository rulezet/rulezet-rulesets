rule TTP_XOR_WriteProcessMemory_f9f4 {
  strings:
    $key_f9f4 = { ae 86 [2] 9c a4 [2] 9a 91 [2] b4 91 [2] 8b 8d }

  condition:
    any of them
}