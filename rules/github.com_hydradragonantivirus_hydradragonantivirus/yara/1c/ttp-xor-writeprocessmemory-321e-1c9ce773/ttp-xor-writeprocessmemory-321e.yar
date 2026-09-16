rule TTP_XOR_WriteProcessMemory_321e {
  strings:
    $key_321e = { 65 6c [2] 57 4e [2] 51 7b [2] 7f 7b [2] 40 67 }

  condition:
    any of them
}