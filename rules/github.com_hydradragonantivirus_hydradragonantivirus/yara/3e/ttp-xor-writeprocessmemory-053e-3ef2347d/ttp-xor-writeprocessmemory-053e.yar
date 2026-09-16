rule TTP_XOR_WriteProcessMemory_053e {
  strings:
    $key_053e = { 52 4c [2] 60 6e [2] 66 5b [2] 48 5b [2] 77 47 }

  condition:
    any of them
}