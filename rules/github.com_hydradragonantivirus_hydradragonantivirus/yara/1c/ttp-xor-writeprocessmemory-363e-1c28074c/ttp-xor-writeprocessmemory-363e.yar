rule TTP_XOR_WriteProcessMemory_363e {
  strings:
    $key_363e = { 61 4c [2] 53 6e [2] 55 5b [2] 7b 5b [2] 44 47 }

  condition:
    any of them
}