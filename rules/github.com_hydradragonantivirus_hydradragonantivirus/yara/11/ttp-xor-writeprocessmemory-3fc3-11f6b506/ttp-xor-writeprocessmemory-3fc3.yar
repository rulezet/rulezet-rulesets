rule TTP_XOR_WriteProcessMemory_3fc3 {
  strings:
    $key_3fc3 = { 68 b1 [2] 5a 93 [2] 5c a6 [2] 72 a6 [2] 4d ba }

  condition:
    any of them
}