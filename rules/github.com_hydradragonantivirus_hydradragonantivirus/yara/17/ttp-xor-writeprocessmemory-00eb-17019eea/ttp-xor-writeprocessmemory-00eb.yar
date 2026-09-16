rule TTP_XOR_WriteProcessMemory_00eb {
  strings:
    $key_00eb = { 57 99 [2] 65 bb [2] 63 8e [2] 4d 8e [2] 72 92 }

  condition:
    any of them
}