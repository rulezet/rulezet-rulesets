rule TTP_XOR_WriteProcessMemory_27eb {
  strings:
    $key_27eb = { 70 99 [2] 42 bb [2] 44 8e [2] 6a 8e [2] 55 92 }

  condition:
    any of them
}