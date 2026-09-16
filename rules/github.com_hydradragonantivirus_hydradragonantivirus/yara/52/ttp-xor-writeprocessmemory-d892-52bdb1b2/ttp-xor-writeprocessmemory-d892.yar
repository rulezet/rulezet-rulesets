rule TTP_XOR_WriteProcessMemory_d892 {
  strings:
    $key_d892 = { 8f e0 [2] bd c2 [2] bb f7 [2] 95 f7 [2] aa eb }

  condition:
    any of them
}