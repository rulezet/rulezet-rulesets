rule TTP_XOR_WriteProcessMemory_dd3b {
  strings:
    $key_dd3b = { 8a 49 [2] b8 6b [2] be 5e [2] 90 5e [2] af 42 }

  condition:
    any of them
}