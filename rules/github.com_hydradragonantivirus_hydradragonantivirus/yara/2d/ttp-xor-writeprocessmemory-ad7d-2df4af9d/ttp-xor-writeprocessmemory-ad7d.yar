rule TTP_XOR_WriteProcessMemory_ad7d {
  strings:
    $key_ad7d = { fa 0f [2] c8 2d [2] ce 18 [2] e0 18 [2] df 04 }

  condition:
    any of them
}