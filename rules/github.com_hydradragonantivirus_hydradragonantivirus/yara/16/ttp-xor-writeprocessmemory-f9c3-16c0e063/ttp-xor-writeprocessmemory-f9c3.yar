rule TTP_XOR_WriteProcessMemory_f9c3 {
  strings:
    $key_f9c3 = { ae b1 [2] 9c 93 [2] 9a a6 [2] b4 a6 [2] 8b ba }

  condition:
    any of them
}