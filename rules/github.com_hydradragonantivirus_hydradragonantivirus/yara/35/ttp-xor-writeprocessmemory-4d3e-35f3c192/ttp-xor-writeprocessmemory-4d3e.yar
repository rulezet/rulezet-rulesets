rule TTP_XOR_WriteProcessMemory_4d3e {
  strings:
    $key_4d3e = { 1a 4c [2] 28 6e [2] 2e 5b [2] 00 5b [2] 3f 47 }

  condition:
    any of them
}