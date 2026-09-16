rule TTP_XOR_WriteProcessMemory_e8c4 {
  strings:
    $key_e8c4 = { bf b6 [2] 8d 94 [2] 8b a1 [2] a5 a1 [2] 9a bd }

  condition:
    any of them
}