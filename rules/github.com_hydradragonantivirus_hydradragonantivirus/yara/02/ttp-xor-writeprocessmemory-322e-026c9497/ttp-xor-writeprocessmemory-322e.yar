rule TTP_XOR_WriteProcessMemory_322e {
  strings:
    $key_322e = { 65 5c [2] 57 7e [2] 51 4b [2] 7f 4b [2] 40 57 }

  condition:
    any of them
}