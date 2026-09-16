rule TTP_XOR_WriteProcessMemory_f92c {
  strings:
    $key_f92c = { ae 5e [2] 9c 7c [2] 9a 49 [2] b4 49 [2] 8b 55 }

  condition:
    any of them
}