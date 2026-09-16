rule TTP_XOR_WriteProcessMemory_0a2e {
  strings:
    $key_0a2e = { 5d 5c [2] 6f 7e [2] 69 4b [2] 47 4b [2] 78 57 }

  condition:
    any of them
}