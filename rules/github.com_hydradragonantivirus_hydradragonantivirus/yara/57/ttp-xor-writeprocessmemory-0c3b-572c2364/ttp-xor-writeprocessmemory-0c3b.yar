rule TTP_XOR_WriteProcessMemory_0c3b {
  strings:
    $key_0c3b = { 5b 49 [2] 69 6b [2] 6f 5e [2] 41 5e [2] 7e 42 }

  condition:
    any of them
}