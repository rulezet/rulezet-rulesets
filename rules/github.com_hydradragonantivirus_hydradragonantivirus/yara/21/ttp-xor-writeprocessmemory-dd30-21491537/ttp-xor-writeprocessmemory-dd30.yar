rule TTP_XOR_WriteProcessMemory_dd30 {
  strings:
    $key_dd30 = { 8a 42 [2] b8 60 [2] be 55 [2] 90 55 [2] af 49 }

  condition:
    any of them
}