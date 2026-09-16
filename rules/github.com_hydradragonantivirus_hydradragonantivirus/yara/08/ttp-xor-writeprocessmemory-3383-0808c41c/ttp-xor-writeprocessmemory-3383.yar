rule TTP_XOR_WriteProcessMemory_3383 {
  strings:
    $key_3383 = { 64 f1 [2] 56 d3 [2] 50 e6 [2] 7e e6 [2] 41 fa }

  condition:
    any of them
}