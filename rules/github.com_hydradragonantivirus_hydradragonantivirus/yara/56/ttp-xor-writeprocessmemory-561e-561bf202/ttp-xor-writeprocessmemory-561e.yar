rule TTP_XOR_WriteProcessMemory_561e {
  strings:
    $key_561e = { 01 6c [2] 33 4e [2] 35 7b [2] 1b 7b [2] 24 67 }

  condition:
    any of them
}