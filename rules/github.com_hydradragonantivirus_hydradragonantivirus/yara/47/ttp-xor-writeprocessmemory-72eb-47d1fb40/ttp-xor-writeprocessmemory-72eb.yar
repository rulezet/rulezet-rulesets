rule TTP_XOR_WriteProcessMemory_72eb {
  strings:
    $key_72eb = { 25 99 [2] 17 bb [2] 11 8e [2] 3f 8e [2] 00 92 }

  condition:
    any of them
}