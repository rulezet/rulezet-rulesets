rule TTP_XOR_WriteProcessMemory_dd01 {
  strings:
    $key_dd01 = { 8a 73 [2] b8 51 [2] be 64 [2] 90 64 [2] af 78 }

  condition:
    any of them
}