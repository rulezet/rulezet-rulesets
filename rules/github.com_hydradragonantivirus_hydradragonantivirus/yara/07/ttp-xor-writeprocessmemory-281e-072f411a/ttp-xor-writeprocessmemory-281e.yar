rule TTP_XOR_WriteProcessMemory_281e {
  strings:
    $key_281e = { 7f 6c [2] 4d 4e [2] 4b 7b [2] 65 7b [2] 5a 67 }

  condition:
    any of them
}