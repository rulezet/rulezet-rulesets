rule TTP_XOR_WriteProcessMemory_eb76 {
  strings:
    $key_eb76 = { bc 04 [2] 8e 26 [2] 88 13 [2] a6 13 [2] 99 0f }

  condition:
    any of them
}