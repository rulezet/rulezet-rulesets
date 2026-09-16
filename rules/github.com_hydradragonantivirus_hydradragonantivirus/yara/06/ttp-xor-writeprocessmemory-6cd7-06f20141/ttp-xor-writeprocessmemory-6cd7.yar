rule TTP_XOR_WriteProcessMemory_6cd7 {
  strings:
    $key_6cd7 = { 3b a5 [2] 09 87 [2] 0f b2 [2] 21 b2 [2] 1e ae }

  condition:
    any of them
}