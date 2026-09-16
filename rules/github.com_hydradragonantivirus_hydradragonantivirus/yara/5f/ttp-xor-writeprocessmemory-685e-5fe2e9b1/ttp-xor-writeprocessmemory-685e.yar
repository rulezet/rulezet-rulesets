rule TTP_XOR_WriteProcessMemory_685e {
  strings:
    $key_685e = { 3f 2c [2] 0d 0e [2] 0b 3b [2] 25 3b [2] 1a 27 }

  condition:
    any of them
}