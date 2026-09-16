rule TTP_XOR_WriteProcessMemory_0c2e {
  strings:
    $key_0c2e = { 5b 5c [2] 69 7e [2] 6f 4b [2] 41 4b [2] 7e 57 }

  condition:
    any of them
}