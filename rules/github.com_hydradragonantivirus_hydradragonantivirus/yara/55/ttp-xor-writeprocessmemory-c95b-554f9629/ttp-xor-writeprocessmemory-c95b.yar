rule TTP_XOR_WriteProcessMemory_c95b {
  strings:
    $key_c95b = { 9e 29 [2] ac 0b [2] aa 3e [2] 84 3e [2] bb 22 }

  condition:
    any of them
}