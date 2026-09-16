rule TTP_XOR_WriteProcessMemory_09c7 {
  strings:
    $key_09c7 = { 5e b5 [2] 6c 97 [2] 6a a2 [2] 44 a2 [2] 7b be }

  condition:
    any of them
}