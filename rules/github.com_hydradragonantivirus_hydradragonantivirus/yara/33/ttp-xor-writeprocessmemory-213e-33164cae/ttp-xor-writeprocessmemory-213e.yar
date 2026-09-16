rule TTP_XOR_WriteProcessMemory_213e {
  strings:
    $key_213e = { 76 4c [2] 44 6e [2] 42 5b [2] 6c 5b [2] 53 47 }

  condition:
    any of them
}