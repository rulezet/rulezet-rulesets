rule TTP_XOR_WriteProcessMemory_132e {
  strings:
    $key_132e = { 44 5c [2] 76 7e [2] 70 4b [2] 5e 4b [2] 61 57 }

  condition:
    any of them
}