rule TTP_XOR_WriteProcessMemory_dd71 {
  strings:
    $key_dd71 = { 8a 03 [2] b8 21 [2] be 14 [2] 90 14 [2] af 08 }

  condition:
    any of them
}