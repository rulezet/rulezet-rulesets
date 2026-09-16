rule TTP_XOR_WriteProcessMemory_271b {
  strings:
    $key_271b = { 70 69 [2] 42 4b [2] 44 7e [2] 6a 7e [2] 55 62 }

  condition:
    any of them
}