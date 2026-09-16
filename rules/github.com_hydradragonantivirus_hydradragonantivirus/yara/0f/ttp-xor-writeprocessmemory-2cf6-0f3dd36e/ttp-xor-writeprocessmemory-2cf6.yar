rule TTP_XOR_WriteProcessMemory_2cf6 {
  strings:
    $key_2cf6 = { 7b 84 [2] 49 a6 [2] 4f 93 [2] 61 93 [2] 5e 8f }

  condition:
    any of them
}