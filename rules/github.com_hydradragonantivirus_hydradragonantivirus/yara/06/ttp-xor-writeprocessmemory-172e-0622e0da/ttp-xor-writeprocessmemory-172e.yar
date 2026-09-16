rule TTP_XOR_WriteProcessMemory_172e {
  strings:
    $key_172e = { 40 5c [2] 72 7e [2] 74 4b [2] 5a 4b [2] 65 57 }

  condition:
    any of them
}