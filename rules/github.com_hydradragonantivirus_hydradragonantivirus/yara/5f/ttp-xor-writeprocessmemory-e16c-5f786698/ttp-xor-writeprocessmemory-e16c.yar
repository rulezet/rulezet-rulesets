rule TTP_XOR_WriteProcessMemory_e16c {
  strings:
    $key_e16c = { b6 1e [2] 84 3c [2] 82 09 [2] ac 09 [2] 93 15 }

  condition:
    any of them
}