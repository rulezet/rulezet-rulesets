rule TTP_XOR_WriteProcessMemory_ad7e {
  strings:
    $key_ad7e = { fa 0c [2] c8 2e [2] ce 1b [2] e0 1b [2] df 07 }

  condition:
    any of them
}