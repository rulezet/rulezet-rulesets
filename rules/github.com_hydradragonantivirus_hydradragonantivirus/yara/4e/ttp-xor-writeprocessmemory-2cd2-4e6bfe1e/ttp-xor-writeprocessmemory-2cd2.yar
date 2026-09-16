rule TTP_XOR_WriteProcessMemory_2cd2 {
  strings:
    $key_2cd2 = { 7b a0 [2] 49 82 [2] 4f b7 [2] 61 b7 [2] 5e ab }

  condition:
    any of them
}