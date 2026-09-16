rule TTP_XOR_WriteProcessMemory_222d {
  strings:
    $key_222d = { 75 5f [2] 47 7d [2] 41 48 [2] 6f 48 [2] 50 54 }

  condition:
    any of them
}