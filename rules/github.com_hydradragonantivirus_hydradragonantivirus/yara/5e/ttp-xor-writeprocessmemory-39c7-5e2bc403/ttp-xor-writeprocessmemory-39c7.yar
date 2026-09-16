rule TTP_XOR_WriteProcessMemory_39c7 {
  strings:
    $key_39c7 = { 6e b5 [2] 5c 97 [2] 5a a2 [2] 74 a2 [2] 4b be }

  condition:
    any of them
}