rule TTP_XOR_WriteProcessMemory_597c {
  strings:
    $key_597c = { 0e 0e [2] 3c 2c [2] 3a 19 [2] 14 19 [2] 2b 05 }

  condition:
    any of them
}