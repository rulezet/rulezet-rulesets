rule TTP_XOR_WriteProcessMemory_1d3c {
  strings:
    $key_1d3c = { 4a 4e [2] 78 6c [2] 7e 59 [2] 50 59 [2] 6f 45 }

  condition:
    any of them
}