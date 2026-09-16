rule TTP_XOR_WriteProcessMemory_ad91 {
  strings:
    $key_ad91 = { fa e3 [2] c8 c1 [2] ce f4 [2] e0 f4 [2] df e8 }

  condition:
    any of them
}