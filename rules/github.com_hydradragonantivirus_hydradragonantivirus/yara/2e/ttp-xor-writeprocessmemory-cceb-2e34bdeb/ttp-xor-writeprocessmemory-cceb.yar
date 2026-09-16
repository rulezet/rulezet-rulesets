rule TTP_XOR_WriteProcessMemory_cceb {
  strings:
    $key_cceb = { 9b 99 [2] a9 bb [2] af 8e [2] 81 8e [2] be 92 }

  condition:
    any of them
}