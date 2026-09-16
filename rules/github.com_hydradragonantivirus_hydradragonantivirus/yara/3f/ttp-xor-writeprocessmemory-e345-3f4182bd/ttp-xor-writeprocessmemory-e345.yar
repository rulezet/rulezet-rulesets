rule TTP_XOR_WriteProcessMemory_e345 {
  strings:
    $key_e345 = { b4 37 [2] 86 15 [2] 80 20 [2] ae 20 [2] 91 3c }

  condition:
    any of them
}