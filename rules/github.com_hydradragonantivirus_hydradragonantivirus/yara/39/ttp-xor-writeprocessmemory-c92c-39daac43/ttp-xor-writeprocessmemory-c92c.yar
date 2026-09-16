rule TTP_XOR_WriteProcessMemory_c92c {
  strings:
    $key_c92c = { 9e 5e [2] ac 7c [2] aa 49 [2] 84 49 [2] bb 55 }

  condition:
    any of them
}