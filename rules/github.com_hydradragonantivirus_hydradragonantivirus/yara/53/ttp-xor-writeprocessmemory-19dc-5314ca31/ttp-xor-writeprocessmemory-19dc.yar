rule TTP_XOR_WriteProcessMemory_19dc {
  strings:
    $key_19dc = { 4e ae [2] 7c 8c [2] 7a b9 [2] 54 b9 [2] 6b a5 }

  condition:
    any of them
}