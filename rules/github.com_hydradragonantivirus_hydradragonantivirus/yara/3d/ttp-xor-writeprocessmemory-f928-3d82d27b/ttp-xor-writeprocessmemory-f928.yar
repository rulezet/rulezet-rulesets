rule TTP_XOR_WriteProcessMemory_f928 {
  strings:
    $key_f928 = { ae 5a [2] 9c 78 [2] 9a 4d [2] b4 4d [2] 8b 51 }

  condition:
    any of them
}