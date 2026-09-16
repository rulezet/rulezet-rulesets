rule TTP_XOR_WriteProcessMemory_4e93 {
  strings:
    $key_4e93 = { 19 e1 [2] 2b c3 [2] 2d f6 [2] 03 f6 [2] 3c ea }

  condition:
    any of them
}