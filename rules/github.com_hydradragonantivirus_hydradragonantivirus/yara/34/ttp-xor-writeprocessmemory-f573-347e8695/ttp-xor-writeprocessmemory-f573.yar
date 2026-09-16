rule TTP_XOR_WriteProcessMemory_f573 {
  strings:
    $key_f573 = { a2 01 [2] 90 23 [2] 96 16 [2] b8 16 [2] 87 0a }

  condition:
    any of them
}