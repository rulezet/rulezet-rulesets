rule TTP_XOR_WriteProcessMemory_3f7e {
  strings:
    $key_3f7e = { 68 0c [2] 5a 2e [2] 5c 1b [2] 72 1b [2] 4d 07 }

  condition:
    any of them
}