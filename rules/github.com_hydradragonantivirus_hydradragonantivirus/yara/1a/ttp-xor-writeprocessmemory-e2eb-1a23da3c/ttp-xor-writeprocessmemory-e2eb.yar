rule TTP_XOR_WriteProcessMemory_e2eb {
  strings:
    $key_e2eb = { b5 99 [2] 87 bb [2] 81 8e [2] af 8e [2] 90 92 }

  condition:
    any of them
}