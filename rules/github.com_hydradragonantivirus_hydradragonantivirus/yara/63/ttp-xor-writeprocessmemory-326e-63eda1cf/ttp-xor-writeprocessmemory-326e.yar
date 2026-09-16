rule TTP_XOR_WriteProcessMemory_326e {
  strings:
    $key_326e = { 65 1c [2] 57 3e [2] 51 0b [2] 7f 0b [2] 40 17 }

  condition:
    any of them
}