rule TTP_XOR_WriteProcessMemory_716e {
  strings:
    $key_716e = { 26 1c [2] 14 3e [2] 12 0b [2] 3c 0b [2] 03 17 }

  condition:
    any of them
}