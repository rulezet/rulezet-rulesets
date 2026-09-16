rule TTP_XOR_WriteProcessMemory_dd32 {
  strings:
    $key_dd32 = { 8a 40 [2] b8 62 [2] be 57 [2] 90 57 [2] af 4b }

  condition:
    any of them
}