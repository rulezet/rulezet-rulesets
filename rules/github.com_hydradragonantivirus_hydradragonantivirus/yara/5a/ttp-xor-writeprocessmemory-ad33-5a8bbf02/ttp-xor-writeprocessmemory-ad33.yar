rule TTP_XOR_WriteProcessMemory_ad33 {
  strings:
    $key_ad33 = { fa 41 [2] c8 63 [2] ce 56 [2] e0 56 [2] df 4a }

  condition:
    any of them
}