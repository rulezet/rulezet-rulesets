rule TTP_XOR_WriteProcessMemory_ad04 {
  strings:
    $key_ad04 = { fa 76 [2] c8 54 [2] ce 61 [2] e0 61 [2] df 7d }

  condition:
    any of them
}