rule TTP_XOR_WriteProcessMemory_f959 {
  strings:
    $key_f959 = { ae 2b [2] 9c 09 [2] 9a 3c [2] b4 3c [2] 8b 20 }

  condition:
    any of them
}