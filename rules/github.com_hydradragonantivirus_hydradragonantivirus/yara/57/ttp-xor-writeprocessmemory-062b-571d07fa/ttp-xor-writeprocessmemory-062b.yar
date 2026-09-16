rule TTP_XOR_WriteProcessMemory_062b {
  strings:
    $key_062b = { 51 59 [2] 63 7b [2] 65 4e [2] 4b 4e [2] 74 52 }

  condition:
    any of them
}