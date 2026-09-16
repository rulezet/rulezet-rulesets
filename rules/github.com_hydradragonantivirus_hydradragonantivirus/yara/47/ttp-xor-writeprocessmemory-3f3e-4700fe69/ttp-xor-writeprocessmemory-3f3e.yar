rule TTP_XOR_WriteProcessMemory_3f3e {
  strings:
    $key_3f3e = { 68 4c [2] 5a 6e [2] 5c 5b [2] 72 5b [2] 4d 47 }

  condition:
    any of them
}