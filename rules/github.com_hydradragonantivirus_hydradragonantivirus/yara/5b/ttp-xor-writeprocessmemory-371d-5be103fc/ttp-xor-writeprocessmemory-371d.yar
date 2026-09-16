rule TTP_XOR_WriteProcessMemory_371d {
  strings:
    $key_371d = { 60 6f [2] 52 4d [2] 54 78 [2] 7a 78 [2] 45 64 }

  condition:
    any of them
}