rule TTP_XOR_WriteProcessMemory_dde1 {
  strings:
    $key_dde1 = { 8a 93 [2] b8 b1 [2] be 84 [2] 90 84 [2] af 98 }

  condition:
    any of them
}