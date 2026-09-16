rule TTP_XOR_WriteProcessMemory_ad28 {
  strings:
    $key_ad28 = { fa 5a [2] c8 78 [2] ce 4d [2] e0 4d [2] df 51 }

  condition:
    any of them
}