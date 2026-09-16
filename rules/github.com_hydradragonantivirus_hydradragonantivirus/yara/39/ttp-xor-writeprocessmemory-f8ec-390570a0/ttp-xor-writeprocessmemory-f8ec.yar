rule TTP_XOR_WriteProcessMemory_f8ec {
  strings:
    $key_f8ec = { af 9e [2] 9d bc [2] 9b 89 [2] b5 89 [2] 8a 95 }

  condition:
    any of them
}