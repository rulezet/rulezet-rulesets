rule TTP_XOR_WriteProcessMemory_667d {
  strings:
    $key_667d = { 31 0f [2] 03 2d [2] 05 18 [2] 2b 18 [2] 14 04 }

  condition:
    any of them
}