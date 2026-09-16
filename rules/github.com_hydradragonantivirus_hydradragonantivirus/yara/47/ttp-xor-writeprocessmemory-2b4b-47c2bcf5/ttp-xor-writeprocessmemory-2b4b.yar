rule TTP_XOR_WriteProcessMemory_2b4b {
  strings:
    $key_2b4b = { 7c 39 [2] 4e 1b [2] 48 2e [2] 66 2e [2] 59 32 }

  condition:
    any of them
}