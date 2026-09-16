rule TTP_XOR_WriteProcessMemory_6782 {
  strings:
    $key_6782 = { 30 f0 [2] 02 d2 [2] 04 e7 [2] 2a e7 [2] 15 fb }

  condition:
    any of them
}