rule TTP_XOR_WriteProcessMemory_4293 {
  strings:
    $key_4293 = { 15 e1 [2] 27 c3 [2] 21 f6 [2] 0f f6 [2] 30 ea }

  condition:
    any of them
}