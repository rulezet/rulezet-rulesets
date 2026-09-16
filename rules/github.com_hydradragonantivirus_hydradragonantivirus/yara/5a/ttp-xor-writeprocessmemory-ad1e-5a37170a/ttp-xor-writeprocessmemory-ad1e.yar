rule TTP_XOR_WriteProcessMemory_ad1e {
  strings:
    $key_ad1e = { fa 6c [2] c8 4e [2] ce 7b [2] e0 7b [2] df 67 }

  condition:
    any of them
}