rule TTP_XOR_WriteProcessMemory_330b {
  strings:
    $key_330b = { 64 79 [2] 56 5b [2] 50 6e [2] 7e 6e [2] 41 72 }

  condition:
    any of them
}