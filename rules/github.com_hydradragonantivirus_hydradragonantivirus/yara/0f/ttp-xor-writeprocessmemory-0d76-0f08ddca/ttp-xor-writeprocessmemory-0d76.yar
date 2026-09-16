rule TTP_XOR_WriteProcessMemory_0d76 {
  strings:
    $key_0d76 = { 5a 04 [2] 68 26 [2] 6e 13 [2] 40 13 [2] 7f 0f }

  condition:
    any of them
}