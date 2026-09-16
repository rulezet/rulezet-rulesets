rule TTP_XOR_WriteProcessMemory_243d {
  strings:
    $key_243d = { 73 4f [2] 41 6d [2] 47 58 [2] 69 58 [2] 56 44 }

  condition:
    any of them
}