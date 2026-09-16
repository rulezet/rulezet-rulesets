rule TTP_XOR_WriteProcessMemory_78eb {
  strings:
    $key_78eb = { 2f 99 [2] 1d bb [2] 1b 8e [2] 35 8e [2] 0a 92 }

  condition:
    any of them
}