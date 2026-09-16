rule TTP_XOR_WriteProcessMemory_ad3b {
  strings:
    $key_ad3b = { fa 49 [2] c8 6b [2] ce 5e [2] e0 5e [2] df 42 }

  condition:
    any of them
}