rule TTP_XOR_WriteProcessMemory_0d3e {
  strings:
    $key_0d3e = { 5a 4c [2] 68 6e [2] 6e 5b [2] 40 5b [2] 7f 47 }

  condition:
    any of them
}