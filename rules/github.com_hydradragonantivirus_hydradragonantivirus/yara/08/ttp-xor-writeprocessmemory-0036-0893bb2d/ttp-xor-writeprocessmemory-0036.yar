rule TTP_XOR_WriteProcessMemory_0036 {
  strings:
    $key_0036 = { 57 44 [2] 65 66 [2] 63 53 [2] 4d 53 [2] 72 4f }

  condition:
    any of them
}