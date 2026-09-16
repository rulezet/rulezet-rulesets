rule TTP_XOR_WriteProcessMemory_ad4d {
  strings:
    $key_ad4d = { fa 3f [2] c8 1d [2] ce 28 [2] e0 28 [2] df 34 }

  condition:
    any of them
}