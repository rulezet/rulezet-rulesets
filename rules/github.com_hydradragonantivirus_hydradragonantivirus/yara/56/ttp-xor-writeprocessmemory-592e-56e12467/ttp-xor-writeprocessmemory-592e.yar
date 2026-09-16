rule TTP_XOR_WriteProcessMemory_592e {
  strings:
    $key_592e = { 0e 5c [2] 3c 7e [2] 3a 4b [2] 14 4b [2] 2b 57 }

  condition:
    any of them
}