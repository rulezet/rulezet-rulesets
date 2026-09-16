rule TTP_XOR_WriteProcessMemory_3f2e {
  strings:
    $key_3f2e = { 68 5c [2] 5a 7e [2] 5c 4b [2] 72 4b [2] 4d 57 }

  condition:
    any of them
}