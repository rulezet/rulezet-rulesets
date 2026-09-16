rule TTP_XOR_WriteProcessMemory_52eb {
  strings:
    $key_52eb = { 05 99 [2] 37 bb [2] 31 8e [2] 1f 8e [2] 20 92 }

  condition:
    any of them
}