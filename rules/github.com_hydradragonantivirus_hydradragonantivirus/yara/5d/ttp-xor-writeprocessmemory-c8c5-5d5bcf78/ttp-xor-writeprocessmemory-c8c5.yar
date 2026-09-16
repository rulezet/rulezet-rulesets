rule TTP_XOR_WriteProcessMemory_c8c5 {
  strings:
    $key_c8c5 = { 9f b7 [2] ad 95 [2] ab a0 [2] 85 a0 [2] ba bc }

  condition:
    any of them
}