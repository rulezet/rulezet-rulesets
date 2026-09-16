rule TTP_XOR_WriteProcessMemory_3eeb {
  strings:
    $key_3eeb = { 69 99 [2] 5b bb [2] 5d 8e [2] 73 8e [2] 4c 92 }

  condition:
    any of them
}