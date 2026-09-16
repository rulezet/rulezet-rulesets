rule TTP_XOR_WriteProcessMemory_627b {
  strings:
    $key_627b = { 35 09 [2] 07 2b [2] 01 1e [2] 2f 1e [2] 10 02 }

  condition:
    any of them
}