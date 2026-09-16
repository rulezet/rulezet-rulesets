rule TTP_XOR_WriteProcessMemory_406e {
  strings:
    $key_406e = { 17 1c [2] 25 3e [2] 23 0b [2] 0d 0b [2] 32 17 }

  condition:
    any of them
}