rule TTP_XOR_WriteProcessMemory_4193 {
  strings:
    $key_4193 = { 16 e1 [2] 24 c3 [2] 22 f6 [2] 0c f6 [2] 33 ea }

  condition:
    any of them
}