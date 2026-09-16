rule TTP_XOR_WriteProcessMemory_ad1d {
  strings:
    $key_ad1d = { fa 6f [2] c8 4d [2] ce 78 [2] e0 78 [2] df 64 }

  condition:
    any of them
}