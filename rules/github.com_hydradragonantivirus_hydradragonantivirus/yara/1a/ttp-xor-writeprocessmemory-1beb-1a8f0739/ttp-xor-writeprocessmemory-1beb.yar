rule TTP_XOR_WriteProcessMemory_1beb {
  strings:
    $key_1beb = { 4c 99 [2] 7e bb [2] 78 8e [2] 56 8e [2] 69 92 }

  condition:
    any of them
}