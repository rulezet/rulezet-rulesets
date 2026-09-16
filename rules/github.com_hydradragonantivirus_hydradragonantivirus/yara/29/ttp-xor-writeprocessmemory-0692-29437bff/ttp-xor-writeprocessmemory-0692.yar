rule TTP_XOR_WriteProcessMemory_0692 {
  strings:
    $key_0692 = { 51 e0 [2] 63 c2 [2] 65 f7 [2] 4b f7 [2] 74 eb }

  condition:
    any of them
}