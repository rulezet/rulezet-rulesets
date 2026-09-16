rule TTP_XOR_WriteProcessMemory_2793 {
  strings:
    $key_2793 = { 70 e1 [2] 42 c3 [2] 44 f6 [2] 6a f6 [2] 55 ea }

  condition:
    any of them
}