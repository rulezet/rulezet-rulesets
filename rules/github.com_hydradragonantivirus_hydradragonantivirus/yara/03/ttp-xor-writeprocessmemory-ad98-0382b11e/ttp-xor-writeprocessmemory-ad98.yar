rule TTP_XOR_WriteProcessMemory_ad98 {
  strings:
    $key_ad98 = { fa ea [2] c8 c8 [2] ce fd [2] e0 fd [2] df e1 }

  condition:
    any of them
}