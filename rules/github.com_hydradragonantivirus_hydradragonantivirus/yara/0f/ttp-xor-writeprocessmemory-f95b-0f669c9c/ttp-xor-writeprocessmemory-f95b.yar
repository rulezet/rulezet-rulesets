rule TTP_XOR_WriteProcessMemory_f95b {
  strings:
    $key_f95b = { ae 29 [2] 9c 0b [2] 9a 3e [2] b4 3e [2] 8b 22 }

  condition:
    any of them
}