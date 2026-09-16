rule TTP_XOR_WriteProcessMemory_006e {
  strings:
    $key_006e = { 57 1c [2] 65 3e [2] 63 0b [2] 4d 0b [2] 72 17 }

  condition:
    any of them
}