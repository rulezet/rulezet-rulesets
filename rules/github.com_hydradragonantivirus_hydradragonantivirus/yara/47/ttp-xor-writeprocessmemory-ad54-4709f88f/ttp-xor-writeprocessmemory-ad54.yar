rule TTP_XOR_WriteProcessMemory_ad54 {
  strings:
    $key_ad54 = { fa 26 [2] c8 04 [2] ce 31 [2] e0 31 [2] df 2d }

  condition:
    any of them
}