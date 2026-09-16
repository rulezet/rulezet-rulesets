rule TTP_XOR_WriteProcessMemory_4d3c {
  strings:
    $key_4d3c = { 1a 4e [2] 28 6c [2] 2e 59 [2] 00 59 [2] 3f 45 }

  condition:
    any of them
}