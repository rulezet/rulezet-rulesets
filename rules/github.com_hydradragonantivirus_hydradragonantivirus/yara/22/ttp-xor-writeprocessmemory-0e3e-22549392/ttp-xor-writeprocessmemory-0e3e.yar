rule TTP_XOR_WriteProcessMemory_0e3e {
  strings:
    $key_0e3e = { 59 4c [2] 6b 6e [2] 6d 5b [2] 43 5b [2] 7c 47 }

  condition:
    any of them
}