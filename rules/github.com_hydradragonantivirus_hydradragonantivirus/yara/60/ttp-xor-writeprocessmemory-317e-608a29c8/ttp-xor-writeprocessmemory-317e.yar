rule TTP_XOR_WriteProcessMemory_317e {
  strings:
    $key_317e = { 66 0c [2] 54 2e [2] 52 1b [2] 7c 1b [2] 43 07 }

  condition:
    any of them
}