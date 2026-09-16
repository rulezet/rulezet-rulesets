rule TTP_XOR_WriteProcessMemory_ad0f {
  strings:
    $key_ad0f = { fa 7d [2] c8 5f [2] ce 6a [2] e0 6a [2] df 76 }

  condition:
    any of them
}