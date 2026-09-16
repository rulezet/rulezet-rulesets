rule TTP_XOR_WriteProcessMemory_251b {
  strings:
    $key_251b = { 72 69 [2] 40 4b [2] 46 7e [2] 68 7e [2] 57 62 }

  condition:
    any of them
}