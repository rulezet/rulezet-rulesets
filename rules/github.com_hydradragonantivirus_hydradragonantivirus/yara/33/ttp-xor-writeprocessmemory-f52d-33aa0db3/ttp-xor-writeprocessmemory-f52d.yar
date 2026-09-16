rule TTP_XOR_WriteProcessMemory_f52d {
  strings:
    $key_f52d = { a2 5f [2] 90 7d [2] 96 48 [2] b8 48 [2] 87 54 }

  condition:
    any of them
}