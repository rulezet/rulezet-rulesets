rule TTP_XOR_WriteProcessMemory_ad3c {
  strings:
    $key_ad3c = { fa 4e [2] c8 6c [2] ce 59 [2] e0 59 [2] df 45 }

  condition:
    any of them
}