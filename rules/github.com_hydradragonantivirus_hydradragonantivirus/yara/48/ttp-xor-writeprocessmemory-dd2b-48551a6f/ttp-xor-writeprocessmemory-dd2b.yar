rule TTP_XOR_WriteProcessMemory_dd2b {
  strings:
    $key_dd2b = { 8a 59 [2] b8 7b [2] be 4e [2] 90 4e [2] af 52 }

  condition:
    any of them
}