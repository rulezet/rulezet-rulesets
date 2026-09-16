rule TTP_XOR_WriteProcessMemory_291b {
  strings:
    $key_291b = { 7e 69 [2] 4c 4b [2] 4a 7e [2] 64 7e [2] 5b 62 }

  condition:
    any of them
}