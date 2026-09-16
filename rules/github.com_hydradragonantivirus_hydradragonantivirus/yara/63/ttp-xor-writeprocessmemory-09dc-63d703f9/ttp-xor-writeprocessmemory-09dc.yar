rule TTP_XOR_WriteProcessMemory_09dc {
  strings:
    $key_09dc = { 5e ae [2] 6c 8c [2] 6a b9 [2] 44 b9 [2] 7b a5 }

  condition:
    any of them
}