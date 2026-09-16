rule TTP_XOR_WriteProcessMemory_052d {
  strings:
    $key_052d = { 52 5f [2] 60 7d [2] 66 48 [2] 48 48 [2] 77 54 }

  condition:
    any of them
}