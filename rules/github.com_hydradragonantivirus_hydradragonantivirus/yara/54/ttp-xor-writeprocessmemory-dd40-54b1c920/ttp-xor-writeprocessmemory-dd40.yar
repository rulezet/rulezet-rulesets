rule TTP_XOR_WriteProcessMemory_dd40 {
  strings:
    $key_dd40 = { 8a 32 [2] b8 10 [2] be 25 [2] 90 25 [2] af 39 }

  condition:
    any of them
}