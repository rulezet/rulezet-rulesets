rule TTP_XOR_WriteProcessMemory_18eb {
  strings:
    $key_18eb = { 4f 99 [2] 7d bb [2] 7b 8e [2] 55 8e [2] 6a 92 }

  condition:
    any of them
}