rule TTP_XOR_WriteProcessMemory_ddf1 {
  strings:
    $key_ddf1 = { 8a 83 [2] b8 a1 [2] be 94 [2] 90 94 [2] af 88 }

  condition:
    any of them
}