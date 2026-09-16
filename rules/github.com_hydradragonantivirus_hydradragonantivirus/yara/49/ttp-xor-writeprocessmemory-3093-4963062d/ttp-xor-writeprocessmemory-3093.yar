rule TTP_XOR_WriteProcessMemory_3093 {
  strings:
    $key_3093 = { 67 e1 [2] 55 c3 [2] 53 f6 [2] 7d f6 [2] 42 ea }

  condition:
    any of them
}