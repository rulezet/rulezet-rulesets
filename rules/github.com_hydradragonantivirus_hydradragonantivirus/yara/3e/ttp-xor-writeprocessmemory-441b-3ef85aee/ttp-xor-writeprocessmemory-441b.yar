rule TTP_XOR_WriteProcessMemory_441b {
  strings:
    $key_441b = { 13 69 [2] 21 4b [2] 27 7e [2] 09 7e [2] 36 62 }

  condition:
    any of them
}