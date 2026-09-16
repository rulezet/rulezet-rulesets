rule TTP_XOR_WriteProcessMemory_7d3e {
  strings:
    $key_7d3e = { 2a 4c [2] 18 6e [2] 1e 5b [2] 30 5b [2] 0f 47 }

  condition:
    any of them
}