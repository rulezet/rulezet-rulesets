rule TTP_XOR_WriteProcessMemory_cfcc {
  strings:
    $key_cfcc = { 98 be [2] aa 9c [2] ac a9 [2] 82 a9 [2] bd b5 }

  condition:
    any of them
}