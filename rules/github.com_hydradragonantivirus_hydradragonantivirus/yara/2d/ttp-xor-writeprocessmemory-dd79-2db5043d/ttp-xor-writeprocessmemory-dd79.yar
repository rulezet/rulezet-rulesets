rule TTP_XOR_WriteProcessMemory_dd79 {
  strings:
    $key_dd79 = { 8a 0b [2] b8 29 [2] be 1c [2] 90 1c [2] af 00 }

  condition:
    any of them
}