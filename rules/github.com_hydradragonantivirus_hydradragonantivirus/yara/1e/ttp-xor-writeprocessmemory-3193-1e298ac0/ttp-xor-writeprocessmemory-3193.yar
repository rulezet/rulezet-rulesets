rule TTP_XOR_WriteProcessMemory_3193 {
  strings:
    $key_3193 = { 66 e1 [2] 54 c3 [2] 52 f6 [2] 7c f6 [2] 43 ea }

  condition:
    any of them
}