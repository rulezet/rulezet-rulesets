rule TTP_XOR_WriteProcessMemory_7e93 {
  strings:
    $key_7e93 = { 29 e1 [2] 1b c3 [2] 1d f6 [2] 33 f6 [2] 0c ea }

  condition:
    any of them
}