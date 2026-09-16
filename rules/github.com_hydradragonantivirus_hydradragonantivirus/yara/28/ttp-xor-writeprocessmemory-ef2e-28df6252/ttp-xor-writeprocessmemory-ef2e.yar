rule TTP_XOR_WriteProcessMemory_ef2e {
  strings:
    $key_ef2e = { b8 5c [2] 8a 7e [2] 8c 4b [2] a2 4b [2] 9d 57 }

  condition:
    any of them
}