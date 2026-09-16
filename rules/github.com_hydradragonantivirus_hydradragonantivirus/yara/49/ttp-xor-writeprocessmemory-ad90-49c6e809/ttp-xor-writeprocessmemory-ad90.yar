rule TTP_XOR_WriteProcessMemory_ad90 {
  strings:
    $key_ad90 = { fa e2 [2] c8 c0 [2] ce f5 [2] e0 f5 [2] df e9 }

  condition:
    any of them
}