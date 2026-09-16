rule TTP_XOR_WriteProcessMemory_f70d {
  strings:
    $key_f70d = { a0 7f [2] 92 5d [2] 94 68 [2] ba 68 [2] 85 74 }

  condition:
    any of them
}