rule TTP_XOR_WriteProcessMemory_3f7b {
  strings:
    $key_3f7b = { 68 09 [2] 5a 2b [2] 5c 1e [2] 72 1e [2] 4d 02 }

  condition:
    any of them
}