rule TTP_XOR_WriteProcessMemory_337e {
  strings:
    $key_337e = { 64 0c [2] 56 2e [2] 50 1b [2] 7e 1b [2] 41 07 }

  condition:
    any of them
}