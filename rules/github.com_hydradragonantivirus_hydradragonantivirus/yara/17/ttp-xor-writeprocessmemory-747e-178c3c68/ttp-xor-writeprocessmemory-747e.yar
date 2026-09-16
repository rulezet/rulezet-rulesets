rule TTP_XOR_WriteProcessMemory_747e {
  strings:
    $key_747e = { 23 0c [2] 11 2e [2] 17 1b [2] 39 1b [2] 06 07 }

  condition:
    any of them
}