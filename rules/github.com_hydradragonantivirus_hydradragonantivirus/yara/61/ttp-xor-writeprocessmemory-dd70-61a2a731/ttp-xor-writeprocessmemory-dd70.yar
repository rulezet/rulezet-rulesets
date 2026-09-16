rule TTP_XOR_WriteProcessMemory_dd70 {
  strings:
    $key_dd70 = { 8a 02 [2] b8 20 [2] be 15 [2] 90 15 [2] af 09 }

  condition:
    any of them
}