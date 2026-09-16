rule TTP_XOR_WriteProcessMemory_165d {
  strings:
    $key_165d = { 41 2f [2] 73 0d [2] 75 38 [2] 5b 38 [2] 64 24 }

  condition:
    any of them
}