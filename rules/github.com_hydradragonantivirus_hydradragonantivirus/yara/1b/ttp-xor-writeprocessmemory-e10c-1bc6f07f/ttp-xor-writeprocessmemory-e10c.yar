rule TTP_XOR_WriteProcessMemory_e10c {
  strings:
    $key_e10c = { b6 7e [2] 84 5c [2] 82 69 [2] ac 69 [2] 93 75 }

  condition:
    any of them
}