rule TTP_XOR_WriteProcessMemory_3785 {
  strings:
    $key_3785 = { 60 f7 [2] 52 d5 [2] 54 e0 [2] 7a e0 [2] 45 fc }

  condition:
    any of them
}