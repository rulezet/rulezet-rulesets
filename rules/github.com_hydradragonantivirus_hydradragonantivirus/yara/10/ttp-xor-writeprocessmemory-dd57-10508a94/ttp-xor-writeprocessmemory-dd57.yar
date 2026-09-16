rule TTP_XOR_WriteProcessMemory_dd57 {
  strings:
    $key_dd57 = { 8a 25 [2] b8 07 [2] be 32 [2] 90 32 [2] af 2e }

  condition:
    any of them
}