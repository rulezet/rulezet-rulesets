rule TTP_XOR_WriteProcessMemory_ad7b {
  strings:
    $key_ad7b = { fa 09 [2] c8 2b [2] ce 1e [2] e0 1e [2] df 02 }

  condition:
    any of them
}