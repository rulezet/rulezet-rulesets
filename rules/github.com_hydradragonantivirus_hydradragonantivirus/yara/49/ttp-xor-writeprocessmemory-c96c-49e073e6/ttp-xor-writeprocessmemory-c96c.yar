rule TTP_XOR_WriteProcessMemory_c96c {
  strings:
    $key_c96c = { 9e 1e [2] ac 3c [2] aa 09 [2] 84 09 [2] bb 15 }

  condition:
    any of them
}