rule TTP_XOR_WriteProcessMemory_09eb {
  strings:
    $key_09eb = { 5e 99 [2] 6c bb [2] 6a 8e [2] 44 8e [2] 7b 92 }

  condition:
    any of them
}