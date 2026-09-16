rule TTP_XOR_WriteProcessMemory_050e {
  strings:
    $key_050e = { 52 7c [2] 60 5e [2] 66 6b [2] 48 6b [2] 77 77 }

  condition:
    any of them
}