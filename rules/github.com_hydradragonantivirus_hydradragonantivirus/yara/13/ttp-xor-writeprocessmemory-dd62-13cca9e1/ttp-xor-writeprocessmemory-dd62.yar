rule TTP_XOR_WriteProcessMemory_dd62 {
  strings:
    $key_dd62 = { 8a 10 [2] b8 32 [2] be 07 [2] 90 07 [2] af 1b }

  condition:
    any of them
}