rule TTP_XOR_WriteProcessMemory_7c7e {
  strings:
    $key_7c7e = { 2b 0c [2] 19 2e [2] 1f 1b [2] 31 1b [2] 0e 07 }

  condition:
    any of them
}