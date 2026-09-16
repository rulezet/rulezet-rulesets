rule TTP_XOR_WriteProcessMemory_39dc {
  strings:
    $key_39dc = { 6e ae [2] 5c 8c [2] 5a b9 [2] 74 b9 [2] 4b a5 }

  condition:
    any of them
}