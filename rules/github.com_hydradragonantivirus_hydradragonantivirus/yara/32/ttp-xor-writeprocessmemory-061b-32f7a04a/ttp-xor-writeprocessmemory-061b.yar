rule TTP_XOR_WriteProcessMemory_061b {
  strings:
    $key_061b = { 51 69 [2] 63 4b [2] 65 7e [2] 4b 7e [2] 74 62 }

  condition:
    any of them
}