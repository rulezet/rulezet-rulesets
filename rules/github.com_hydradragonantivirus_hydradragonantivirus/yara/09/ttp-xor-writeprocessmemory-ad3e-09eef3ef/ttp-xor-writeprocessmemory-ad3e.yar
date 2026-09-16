rule TTP_XOR_WriteProcessMemory_ad3e {
  strings:
    $key_ad3e = { fa 4c [2] c8 6e [2] ce 5b [2] e0 5b [2] df 47 }

  condition:
    any of them
}