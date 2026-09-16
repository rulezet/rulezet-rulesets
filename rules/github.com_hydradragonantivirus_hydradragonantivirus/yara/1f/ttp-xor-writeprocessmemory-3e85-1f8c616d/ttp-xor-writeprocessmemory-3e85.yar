rule TTP_XOR_WriteProcessMemory_3e85 {
  strings:
    $key_3e85 = { 69 f7 [2] 5b d5 [2] 5d e0 [2] 73 e0 [2] 4c fc }

  condition:
    any of them
}