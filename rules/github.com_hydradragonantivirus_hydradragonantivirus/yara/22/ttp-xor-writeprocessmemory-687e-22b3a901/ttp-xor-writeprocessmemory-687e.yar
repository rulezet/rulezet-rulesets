rule TTP_XOR_WriteProcessMemory_687e {
  strings:
    $key_687e = { 3f 0c [2] 0d 2e [2] 0b 1b [2] 25 1b [2] 1a 07 }

  condition:
    any of them
}