rule TTP_XOR_WriteProcessMemory_06b3 {
  strings:
    $key_06b3 = { 51 c1 [2] 63 e3 [2] 65 d6 [2] 4b d6 [2] 74 ca }

  condition:
    any of them
}