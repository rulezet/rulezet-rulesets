rule TTP_XOR_WriteProcessMemory_015b {
  strings:
    $key_015b = { 56 29 [2] 64 0b [2] 62 3e [2] 4c 3e [2] 73 22 }

  condition:
    any of them
}