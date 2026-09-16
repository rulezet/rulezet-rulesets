rule TTP_XOR_WriteProcessMemory_1193 {
  strings:
    $key_1193 = { 46 e1 [2] 74 c3 [2] 72 f6 [2] 5c f6 [2] 63 ea }

  condition:
    any of them
}