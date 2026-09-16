rule TTP_XOR_WriteProcessMemory_4230 {
  strings:
    $key_4230 = { 15 42 [2] 27 60 [2] 21 55 [2] 0f 55 [2] 30 49 }

  condition:
    any of them
}