rule TTP_XOR_WriteProcessMemory_d88d {
  strings:
    $key_d88d = { 8f ff [2] bd dd [2] bb e8 [2] 95 e8 [2] aa f4 }

  condition:
    any of them
}