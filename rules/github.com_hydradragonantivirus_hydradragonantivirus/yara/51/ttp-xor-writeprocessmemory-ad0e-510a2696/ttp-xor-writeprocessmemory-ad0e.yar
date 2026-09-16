rule TTP_XOR_WriteProcessMemory_ad0e {
  strings:
    $key_ad0e = { fa 7c [2] c8 5e [2] ce 6b [2] e0 6b [2] df 77 }

  condition:
    any of them
}