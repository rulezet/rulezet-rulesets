rule TTP_XOR_WriteProcessMemory_2f2e {
  strings:
    $key_2f2e = { 78 5c [2] 4a 7e [2] 4c 4b [2] 62 4b [2] 5d 57 }

  condition:
    any of them
}