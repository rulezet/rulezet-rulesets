rule TTP_XOR_WriteProcessMemory_ad03 {
  strings:
    $key_ad03 = { fa 71 [2] c8 53 [2] ce 66 [2] e0 66 [2] df 7a }

  condition:
    any of them
}