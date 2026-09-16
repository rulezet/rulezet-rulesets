rule TTP_XOR_WriteProcessMemory_dd55 {
  strings:
    $key_dd55 = { 8a 27 [2] b8 05 [2] be 30 [2] 90 30 [2] af 2c }

  condition:
    any of them
}