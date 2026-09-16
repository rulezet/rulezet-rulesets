rule TTP_XOR_WriteProcessMemory_dd59 {
  strings:
    $key_dd59 = { 8a 2b [2] b8 09 [2] be 3c [2] 90 3c [2] af 20 }

  condition:
    any of them
}