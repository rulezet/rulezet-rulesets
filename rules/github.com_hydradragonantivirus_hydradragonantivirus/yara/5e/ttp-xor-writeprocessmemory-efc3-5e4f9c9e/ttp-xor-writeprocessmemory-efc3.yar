rule TTP_XOR_WriteProcessMemory_efc3 {
  strings:
    $key_efc3 = { b8 b1 [2] 8a 93 [2] 8c a6 [2] a2 a6 [2] 9d ba }

  condition:
    any of them
}