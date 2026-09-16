rule TTP_XOR_WriteProcessMemory_f910 {
  strings:
    $key_f910 = { ae 62 [2] 9c 40 [2] 9a 75 [2] b4 75 [2] 8b 69 }

  condition:
    any of them
}