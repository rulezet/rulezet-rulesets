rule TTP_XOR_WriteProcessMemory_533e {
  strings:
    $key_533e = { 04 4c [2] 36 6e [2] 30 5b [2] 1e 5b [2] 21 47 }

  condition:
    any of them
}