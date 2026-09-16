rule TTP_XOR_WriteProcessMemory_adfb {
  strings:
    $key_adfb = { fa 89 [2] c8 ab [2] ce 9e [2] e0 9e [2] df 82 }

  condition:
    any of them
}