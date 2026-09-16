rule TTP_XOR_WriteProcessMemory_dd52 {
  strings:
    $key_dd52 = { 8a 20 [2] b8 02 [2] be 37 [2] 90 37 [2] af 2b }

  condition:
    any of them
}