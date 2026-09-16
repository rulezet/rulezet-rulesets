rule TTP_XOR_WriteProcessMemory_431b {
  strings:
    $key_431b = { 14 69 [2] 26 4b [2] 20 7e [2] 0e 7e [2] 31 62 }

  condition:
    any of them
}