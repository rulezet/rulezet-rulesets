rule TTP_XOR_WriteProcessMemory_0636 {
  strings:
    $key_0636 = { 51 44 [2] 63 66 [2] 65 53 [2] 4b 53 [2] 74 4f }

  condition:
    any of them
}