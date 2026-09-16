rule TTP_XOR_WriteProcessMemory_6eeb {
  strings:
    $key_6eeb = { 39 99 [2] 0b bb [2] 0d 8e [2] 23 8e [2] 1c 92 }

  condition:
    any of them
}