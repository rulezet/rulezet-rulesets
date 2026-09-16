rule TTP_XOR_WriteProcessMemory_0f7e {
  strings:
    $key_0f7e = { 58 0c [2] 6a 2e [2] 6c 1b [2] 42 1b [2] 7d 07 }

  condition:
    any of them
}