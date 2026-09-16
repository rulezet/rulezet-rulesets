rule TTP_XOR_WriteProcessMemory_c81d {
  strings:
    $key_c81d = { 9f 6f [2] ad 4d [2] ab 78 [2] 85 78 [2] ba 64 }

  condition:
    any of them
}