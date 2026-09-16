rule TTP_XOR_WriteProcessMemory_423d {
  strings:
    $key_423d = { 15 4f [2] 27 6d [2] 21 58 [2] 0f 58 [2] 30 44 }

  condition:
    any of them
}