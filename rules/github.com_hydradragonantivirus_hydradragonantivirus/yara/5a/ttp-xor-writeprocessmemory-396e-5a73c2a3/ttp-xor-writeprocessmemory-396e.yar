rule TTP_XOR_WriteProcessMemory_396e {
  strings:
    $key_396e = { 6e 1c [2] 5c 3e [2] 5a 0b [2] 74 0b [2] 4b 17 }

  condition:
    any of them
}