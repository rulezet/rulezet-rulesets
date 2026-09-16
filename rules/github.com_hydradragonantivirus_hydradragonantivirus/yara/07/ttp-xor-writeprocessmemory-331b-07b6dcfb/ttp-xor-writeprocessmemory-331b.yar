rule TTP_XOR_WriteProcessMemory_331b {
  strings:
    $key_331b = { 64 69 [2] 56 4b [2] 50 7e [2] 7e 7e [2] 41 62 }

  condition:
    any of them
}