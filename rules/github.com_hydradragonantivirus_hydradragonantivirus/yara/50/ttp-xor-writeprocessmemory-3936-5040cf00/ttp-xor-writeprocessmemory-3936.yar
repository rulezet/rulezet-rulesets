rule TTP_XOR_WriteProcessMemory_3936 {
  strings:
    $key_3936 = { 6e 44 [2] 5c 66 [2] 5a 53 [2] 74 53 [2] 4b 4f }

  condition:
    any of them
}