rule TTP_XOR_WriteProcessMemory_f9fc {
  strings:
    $key_f9fc = { ae 8e [2] 9c ac [2] 9a 99 [2] b4 99 [2] 8b 85 }

  condition:
    any of them
}