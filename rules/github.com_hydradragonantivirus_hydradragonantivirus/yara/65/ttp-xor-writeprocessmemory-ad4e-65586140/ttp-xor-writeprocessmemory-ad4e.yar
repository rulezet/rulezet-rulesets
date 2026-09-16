rule TTP_XOR_WriteProcessMemory_ad4e {
  strings:
    $key_ad4e = { fa 3c [2] c8 1e [2] ce 2b [2] e0 2b [2] df 37 }

  condition:
    any of them
}