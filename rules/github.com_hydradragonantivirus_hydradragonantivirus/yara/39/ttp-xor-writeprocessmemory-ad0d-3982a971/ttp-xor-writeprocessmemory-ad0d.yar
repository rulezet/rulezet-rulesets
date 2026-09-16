rule TTP_XOR_WriteProcessMemory_ad0d {
  strings:
    $key_ad0d = { fa 7f [2] c8 5d [2] ce 68 [2] e0 68 [2] df 74 }

  condition:
    any of them
}