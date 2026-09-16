rule TTP_XOR_WriteProcessMemory_dd44 {
  strings:
    $key_dd44 = { 8a 36 [2] b8 14 [2] be 21 [2] 90 21 [2] af 3d }

  condition:
    any of them
}