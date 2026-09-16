rule TTP_XOR_WriteProcessMemory_dd02 {
  strings:
    $key_dd02 = { 8a 70 [2] b8 52 [2] be 67 [2] 90 67 [2] af 7b }

  condition:
    any of them
}