rule TTP_XOR_WriteProcessMemory_335d {
  strings:
    $key_335d = { 64 2f [2] 56 0d [2] 50 38 [2] 7e 38 [2] 41 24 }

  condition:
    any of them
}