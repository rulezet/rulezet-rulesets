rule TTP_XOR_WriteProcessMemory_dd0e {
  strings:
    $key_dd0e = { 8a 7c [2] b8 5e [2] be 6b [2] 90 6b [2] af 77 }

  condition:
    any of them
}