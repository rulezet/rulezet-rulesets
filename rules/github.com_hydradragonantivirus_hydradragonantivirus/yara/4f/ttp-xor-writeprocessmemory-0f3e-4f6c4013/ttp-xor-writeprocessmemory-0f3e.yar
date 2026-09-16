rule TTP_XOR_WriteProcessMemory_0f3e {
  strings:
    $key_0f3e = { 58 4c [2] 6a 6e [2] 6c 5b [2] 42 5b [2] 7d 47 }

  condition:
    any of them
}