rule TTP_XOR_WriteProcessMemory_627e {
  strings:
    $key_627e = { 35 0c [2] 07 2e [2] 01 1b [2] 2f 1b [2] 10 07 }

  condition:
    any of them
}