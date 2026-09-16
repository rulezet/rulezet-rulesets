rule TTP_XOR_WriteProcessMemory_673d {
  strings:
    $key_673d = { 30 4f [2] 02 6d [2] 04 58 [2] 2a 58 [2] 15 44 }

  condition:
    any of them
}