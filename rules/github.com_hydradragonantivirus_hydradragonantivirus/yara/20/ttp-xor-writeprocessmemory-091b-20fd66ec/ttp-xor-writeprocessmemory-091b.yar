rule TTP_XOR_WriteProcessMemory_091b {
  strings:
    $key_091b = { 5e 69 [2] 6c 4b [2] 6a 7e [2] 44 7e [2] 7b 62 }

  condition:
    any of them
}