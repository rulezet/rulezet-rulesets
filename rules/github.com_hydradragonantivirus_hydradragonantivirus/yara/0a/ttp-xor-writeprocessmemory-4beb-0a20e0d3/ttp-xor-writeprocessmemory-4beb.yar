rule TTP_XOR_WriteProcessMemory_4beb {
  strings:
    $key_4beb = { 1c 99 [2] 2e bb [2] 28 8e [2] 06 8e [2] 39 92 }

  condition:
    any of them
}