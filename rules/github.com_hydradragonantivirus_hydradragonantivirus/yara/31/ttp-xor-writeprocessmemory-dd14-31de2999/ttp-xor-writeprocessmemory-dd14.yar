rule TTP_XOR_WriteProcessMemory_dd14 {
  strings:
    $key_dd14 = { 8a 66 [2] b8 44 [2] be 71 [2] 90 71 [2] af 6d }

  condition:
    any of them
}