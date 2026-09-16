rule TTP_XOR_WriteProcessMemory_29dc {
  strings:
    $key_29dc = { 7e ae [2] 4c 8c [2] 4a b9 [2] 64 b9 [2] 5b a5 }

  condition:
    any of them
}