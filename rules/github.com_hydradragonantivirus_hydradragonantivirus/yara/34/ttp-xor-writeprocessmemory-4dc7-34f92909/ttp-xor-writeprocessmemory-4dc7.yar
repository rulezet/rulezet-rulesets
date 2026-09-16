rule TTP_XOR_WriteProcessMemory_4dc7 {
  strings:
    $key_4dc7 = { 1a b5 [2] 28 97 [2] 2e a2 [2] 00 a2 [2] 3f be }

  condition:
    any of them
}