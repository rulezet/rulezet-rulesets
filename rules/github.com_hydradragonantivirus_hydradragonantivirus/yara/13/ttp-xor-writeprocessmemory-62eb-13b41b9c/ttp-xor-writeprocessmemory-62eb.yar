rule TTP_XOR_WriteProcessMemory_62eb {
  strings:
    $key_62eb = { 35 99 [2] 07 bb [2] 01 8e [2] 2f 8e [2] 10 92 }

  condition:
    any of them
}