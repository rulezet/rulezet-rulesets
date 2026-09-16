rule TTP_XOR_WriteProcessMemory_ad32 {
  strings:
    $key_ad32 = { fa 40 [2] c8 62 [2] ce 57 [2] e0 57 [2] df 4b }

  condition:
    any of them
}