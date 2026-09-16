rule TTP_XOR_WriteProcessMemory_ad38 {
  strings:
    $key_ad38 = { fa 4a [2] c8 68 [2] ce 5d [2] e0 5d [2] df 41 }

  condition:
    any of them
}