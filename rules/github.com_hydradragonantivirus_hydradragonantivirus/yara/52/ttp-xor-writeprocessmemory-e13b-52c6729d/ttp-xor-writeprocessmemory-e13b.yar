rule TTP_XOR_WriteProcessMemory_e13b {
  strings:
    $key_e13b = { b6 49 [2] 84 6b [2] 82 5e [2] ac 5e [2] 93 42 }

  condition:
    any of them
}