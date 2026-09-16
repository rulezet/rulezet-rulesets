rule TTP_XOR_WriteProcessMemory_3dc7 {
  strings:
    $key_3dc7 = { 6a b5 [2] 58 97 [2] 5e a2 [2] 70 a2 [2] 4f be }

  condition:
    any of them
}