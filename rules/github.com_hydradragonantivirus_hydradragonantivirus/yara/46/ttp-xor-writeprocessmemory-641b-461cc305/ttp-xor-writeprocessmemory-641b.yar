rule TTP_XOR_WriteProcessMemory_641b {
  strings:
    $key_641b = { 33 69 [2] 01 4b [2] 07 7e [2] 29 7e [2] 16 62 }

  condition:
    any of them
}