rule TTP_XOR_WriteProcessMemory_3c2e {
  strings:
    $key_3c2e = { 6b 5c [2] 59 7e [2] 5f 4b [2] 71 4b [2] 4e 57 }

  condition:
    any of them
}