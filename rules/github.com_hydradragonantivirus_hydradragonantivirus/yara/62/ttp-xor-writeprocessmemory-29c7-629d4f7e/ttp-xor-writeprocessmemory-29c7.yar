rule TTP_XOR_WriteProcessMemory_29c7 {
  strings:
    $key_29c7 = { 7e b5 [2] 4c 97 [2] 4a a2 [2] 64 a2 [2] 5b be }

  condition:
    any of them
}