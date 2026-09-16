rule TTP_XOR_WriteProcessMemory_f51b {
  strings:
    $key_f51b = { a2 69 [2] 90 4b [2] 96 7e [2] b8 7e [2] 87 62 }

  condition:
    any of them
}