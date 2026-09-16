rule TTP_XOR_WriteProcessMemory_153d {
  strings:
    $key_153d = { 42 4f [2] 70 6d [2] 76 58 [2] 58 58 [2] 67 44 }

  condition:
    any of them
}