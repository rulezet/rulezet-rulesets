rule TTP_XOR_WriteProcessMemory_320b {
  strings:
    $key_320b = { 65 79 [2] 57 5b [2] 51 6e [2] 7f 6e [2] 40 72 }

  condition:
    any of them
}