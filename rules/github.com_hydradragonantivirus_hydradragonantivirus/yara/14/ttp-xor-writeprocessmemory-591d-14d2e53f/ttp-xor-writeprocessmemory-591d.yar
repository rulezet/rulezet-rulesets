rule TTP_XOR_WriteProcessMemory_591d {
  strings:
    $key_591d = { 0e 6f [2] 3c 4d [2] 3a 78 [2] 14 78 [2] 2b 64 }

  condition:
    any of them
}