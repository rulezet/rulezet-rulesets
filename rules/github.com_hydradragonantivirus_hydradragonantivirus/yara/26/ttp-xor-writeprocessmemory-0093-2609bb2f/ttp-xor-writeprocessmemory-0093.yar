rule TTP_XOR_WriteProcessMemory_0093 {
  strings:
    $key_0093 = { 57 e1 [2] 65 c3 [2] 63 f6 [2] 4d f6 [2] 72 ea }

  condition:
    any of them
}