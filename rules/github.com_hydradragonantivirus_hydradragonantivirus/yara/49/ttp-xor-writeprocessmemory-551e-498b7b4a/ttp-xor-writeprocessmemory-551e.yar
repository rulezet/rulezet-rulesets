rule TTP_XOR_WriteProcessMemory_551e {
  strings:
    $key_551e = { 02 6c [2] 30 4e [2] 36 7b [2] 18 7b [2] 27 67 }

  condition:
    any of them
}