rule TTP_XOR_WriteProcessMemory_786e {
  strings:
    $key_786e = { 2f 1c [2] 1d 3e [2] 1b 0b [2] 35 0b [2] 0a 17 }

  condition:
    any of them
}