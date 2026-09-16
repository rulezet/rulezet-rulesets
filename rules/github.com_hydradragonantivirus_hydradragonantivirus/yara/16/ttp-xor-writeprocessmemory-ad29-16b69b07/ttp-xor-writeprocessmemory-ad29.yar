rule TTP_XOR_WriteProcessMemory_ad29 {
  strings:
    $key_ad29 = { fa 5b [2] c8 79 [2] ce 4c [2] e0 4c [2] df 50 }

  condition:
    any of them
}