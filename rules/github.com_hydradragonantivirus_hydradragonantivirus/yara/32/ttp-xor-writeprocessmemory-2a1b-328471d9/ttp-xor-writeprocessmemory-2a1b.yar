rule TTP_XOR_WriteProcessMemory_2a1b {
  strings:
    $key_2a1b = { 7d 69 [2] 4f 4b [2] 49 7e [2] 67 7e [2] 58 62 }

  condition:
    any of them
}