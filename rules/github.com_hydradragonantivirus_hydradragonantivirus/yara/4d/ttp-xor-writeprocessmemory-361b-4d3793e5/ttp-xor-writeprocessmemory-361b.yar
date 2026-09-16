rule TTP_XOR_WriteProcessMemory_361b {
  strings:
    $key_361b = { 61 69 [2] 53 4b [2] 55 7e [2] 7b 7e [2] 44 62 }

  condition:
    any of them
}