rule TTP_XOR_WriteProcessMemory_f9f8 {
  strings:
    $key_f9f8 = { ae 8a [2] 9c a8 [2] 9a 9d [2] b4 9d [2] 8b 81 }

  condition:
    any of them
}