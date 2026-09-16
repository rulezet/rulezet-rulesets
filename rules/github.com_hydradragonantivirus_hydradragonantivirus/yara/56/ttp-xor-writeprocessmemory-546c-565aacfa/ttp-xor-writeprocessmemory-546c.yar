rule TTP_XOR_WriteProcessMemory_546c {
  strings:
    $key_546c = { 03 1e [2] 31 3c [2] 37 09 [2] 19 09 [2] 26 15 }

  condition:
    any of them
}