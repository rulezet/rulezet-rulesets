rule TTP_XOR_WriteProcessMemory_202e {
  strings:
    $key_202e = { 77 5c [2] 45 7e [2] 43 4b [2] 6d 4b [2] 52 57 }

  condition:
    any of them
}