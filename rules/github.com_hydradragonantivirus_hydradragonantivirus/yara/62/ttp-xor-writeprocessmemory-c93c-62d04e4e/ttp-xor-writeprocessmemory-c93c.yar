rule TTP_XOR_WriteProcessMemory_c93c {
  strings:
    $key_c93c = { 9e 4e [2] ac 6c [2] aa 59 [2] 84 59 [2] bb 45 }

  condition:
    any of them
}