rule TTP_XOR_WriteProcessMemory_162d {
  strings:
    $key_162d = { 41 5f [2] 73 7d [2] 75 48 [2] 5b 48 [2] 64 54 }

  condition:
    any of them
}