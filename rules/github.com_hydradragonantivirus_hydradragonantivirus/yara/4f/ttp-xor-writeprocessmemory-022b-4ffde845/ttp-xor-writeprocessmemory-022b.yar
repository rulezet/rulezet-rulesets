rule TTP_XOR_WriteProcessMemory_022b {
  strings:
    $key_022b = { 55 59 [2] 67 7b [2] 61 4e [2] 4f 4e [2] 70 52 }

  condition:
    any of them
}