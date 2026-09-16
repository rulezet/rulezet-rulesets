rule TTP_XOR_WriteProcessMemory_dd5e {
  strings:
    $key_dd5e = { 8a 2c [2] b8 0e [2] be 3b [2] 90 3b [2] af 27 }

  condition:
    any of them
}