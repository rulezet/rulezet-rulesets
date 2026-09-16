rule TTP_XOR_WriteProcessMemory_ef76 {
  strings:
    $key_ef76 = { b8 04 [2] 8a 26 [2] 8c 13 [2] a2 13 [2] 9d 0f }

  condition:
    any of them
}