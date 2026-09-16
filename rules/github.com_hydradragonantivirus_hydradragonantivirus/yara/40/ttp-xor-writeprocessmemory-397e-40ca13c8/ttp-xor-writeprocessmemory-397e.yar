rule TTP_XOR_WriteProcessMemory_397e {
  strings:
    $key_397e = { 6e 0c [2] 5c 2e [2] 5a 1b [2] 74 1b [2] 4b 07 }

  condition:
    any of them
}