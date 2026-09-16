rule TTP_XOR_WriteProcessMemory_c82d {
  strings:
    $key_c82d = { 9f 5f [2] ad 7d [2] ab 48 [2] 85 48 [2] ba 54 }

  condition:
    any of them
}