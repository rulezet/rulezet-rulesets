rule TTP_XOR_WriteProcessMemory_c94c {
  strings:
    $key_c94c = { 9e 3e [2] ac 1c [2] aa 29 [2] 84 29 [2] bb 35 }

  condition:
    any of them
}