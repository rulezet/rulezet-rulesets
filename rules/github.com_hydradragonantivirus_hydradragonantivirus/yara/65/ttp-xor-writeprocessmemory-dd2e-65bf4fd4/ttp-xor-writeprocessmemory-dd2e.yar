rule TTP_XOR_WriteProcessMemory_dd2e {
  strings:
    $key_dd2e = { 8a 5c [2] b8 7e [2] be 4b [2] 90 4b [2] af 57 }

  condition:
    any of them
}