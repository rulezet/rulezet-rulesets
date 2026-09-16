rule TTP_XOR_WriteProcessMemory_2b3b {
  strings:
    $key_2b3b = { 7c 49 [2] 4e 6b [2] 48 5e [2] 66 5e [2] 59 42 }

  condition:
    any of them
}