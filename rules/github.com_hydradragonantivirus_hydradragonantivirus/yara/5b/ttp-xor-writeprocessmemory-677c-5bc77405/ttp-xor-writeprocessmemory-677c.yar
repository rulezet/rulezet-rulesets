rule TTP_XOR_WriteProcessMemory_677c {
  strings:
    $key_677c = { 30 0e [2] 02 2c [2] 04 19 [2] 2a 19 [2] 15 05 }

  condition:
    any of them
}