rule TTP_XOR_WriteProcessMemory_131d {
  strings:
    $key_131d = { 44 6f [2] 76 4d [2] 70 78 [2] 5e 78 [2] 61 64 }

  condition:
    any of them
}