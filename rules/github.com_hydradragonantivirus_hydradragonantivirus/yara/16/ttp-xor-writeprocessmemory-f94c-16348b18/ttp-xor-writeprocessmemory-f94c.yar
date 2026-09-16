rule TTP_XOR_WriteProcessMemory_f94c {
  strings:
    $key_f94c = { ae 3e [2] 9c 1c [2] 9a 29 [2] b4 29 [2] 8b 35 }

  condition:
    any of them
}