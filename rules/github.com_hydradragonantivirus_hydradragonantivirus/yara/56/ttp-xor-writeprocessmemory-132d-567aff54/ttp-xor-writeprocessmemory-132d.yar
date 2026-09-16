rule TTP_XOR_WriteProcessMemory_132d {
  strings:
    $key_132d = { 44 5f [2] 76 7d [2] 70 48 [2] 5e 48 [2] 61 54 }

  condition:
    any of them
}