rule TTP_XOR_WriteProcessMemory_f976 {
  strings:
    $key_f976 = { ae 04 [2] 9c 26 [2] 9a 13 [2] b4 13 [2] 8b 0f }

  condition:
    any of them
}