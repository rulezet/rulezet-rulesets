rule TTP_XOR_WriteProcessMemory_f91e {
  strings:
    $key_f91e = { ae 6c [2] 9c 4e [2] 9a 7b [2] b4 7b [2] 8b 67 }

  condition:
    any of them
}