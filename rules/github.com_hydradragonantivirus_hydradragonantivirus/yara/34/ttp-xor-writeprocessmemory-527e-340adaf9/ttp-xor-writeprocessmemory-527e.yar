rule TTP_XOR_WriteProcessMemory_527e {
  strings:
    $key_527e = { 05 0c [2] 37 2e [2] 31 1b [2] 1f 1b [2] 20 07 }

  condition:
    any of them
}