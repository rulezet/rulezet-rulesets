rule TTP_XOR_WriteProcessMemory_ad6c {
  strings:
    $key_ad6c = { fa 1e [2] c8 3c [2] ce 09 [2] e0 09 [2] df 15 }

  condition:
    any of them
}