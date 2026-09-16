rule TTP_XOR_WriteProcessMemory_dd04 {
  strings:
    $key_dd04 = { 8a 76 [2] b8 54 [2] be 61 [2] 90 61 [2] af 7d }

  condition:
    any of them
}