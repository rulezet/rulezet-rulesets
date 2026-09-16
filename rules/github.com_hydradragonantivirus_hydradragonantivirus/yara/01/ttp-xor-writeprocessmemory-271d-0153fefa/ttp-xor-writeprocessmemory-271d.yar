rule TTP_XOR_WriteProcessMemory_271d {
  strings:
    $key_271d = { 70 6f [2] 42 4d [2] 44 78 [2] 6a 78 [2] 55 64 }

  condition:
    any of them
}