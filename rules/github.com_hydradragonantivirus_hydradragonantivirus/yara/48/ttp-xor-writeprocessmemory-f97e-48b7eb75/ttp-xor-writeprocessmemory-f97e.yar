rule TTP_XOR_WriteProcessMemory_f97e {
  strings:
    $key_f97e = { ae 0c [2] 9c 2e [2] 9a 1b [2] b4 1b [2] 8b 07 }

  condition:
    any of them
}