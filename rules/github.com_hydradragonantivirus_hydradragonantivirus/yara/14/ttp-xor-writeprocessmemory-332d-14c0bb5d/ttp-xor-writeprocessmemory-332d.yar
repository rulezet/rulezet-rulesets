rule TTP_XOR_WriteProcessMemory_332d {
  strings:
    $key_332d = { 64 5f [2] 56 7d [2] 50 48 [2] 7e 48 [2] 41 54 }

  condition:
    any of them
}