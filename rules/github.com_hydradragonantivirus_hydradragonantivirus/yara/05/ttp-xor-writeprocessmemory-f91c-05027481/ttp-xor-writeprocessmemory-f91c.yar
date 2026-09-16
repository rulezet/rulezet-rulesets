rule TTP_XOR_WriteProcessMemory_f91c {
  strings:
    $key_f91c = { ae 6e [2] 9c 4c [2] 9a 79 [2] b4 79 [2] 8b 65 }

  condition:
    any of them
}