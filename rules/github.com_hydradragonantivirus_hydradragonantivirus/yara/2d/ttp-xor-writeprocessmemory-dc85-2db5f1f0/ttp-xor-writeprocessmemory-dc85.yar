rule TTP_XOR_WriteProcessMemory_dc85 {
  strings:
    $key_dc85 = { 8b f7 [2] b9 d5 [2] bf e0 [2] 91 e0 [2] ae fc }

  condition:
    any of them
}