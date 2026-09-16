rule TTP_XOR_WriteProcessMemory_205c {
  strings:
    $key_205c = { 77 2e [2] 45 0c [2] 43 39 [2] 6d 39 [2] 52 25 }

  condition:
    any of them
}