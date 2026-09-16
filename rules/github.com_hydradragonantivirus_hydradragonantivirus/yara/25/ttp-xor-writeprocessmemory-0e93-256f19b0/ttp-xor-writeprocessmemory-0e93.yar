rule TTP_XOR_WriteProcessMemory_0e93 {
  strings:
    $key_0e93 = { 59 e1 [2] 6b c3 [2] 6d f6 [2] 43 f6 [2] 7c ea }

  condition:
    any of them
}