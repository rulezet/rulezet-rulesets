rule TTP_XOR_WriteProcessMemory_4ec7 {
  strings:
    $key_4ec7 = { 19 b5 [2] 2b 97 [2] 2d a2 [2] 03 a2 [2] 3c be }

  condition:
    any of them
}