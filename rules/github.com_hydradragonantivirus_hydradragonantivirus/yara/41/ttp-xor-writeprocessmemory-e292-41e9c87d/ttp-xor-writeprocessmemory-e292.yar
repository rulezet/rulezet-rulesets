rule TTP_XOR_WriteProcessMemory_e292 {
  strings:
    $key_e292 = { b5 e0 [2] 87 c2 [2] 81 f7 [2] af f7 [2] 90 eb }

  condition:
    any of them
}