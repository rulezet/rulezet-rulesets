rule TTP_XOR_WriteProcessMemory_ad2f {
  strings:
    $key_ad2f = { fa 5d [2] c8 7f [2] ce 4a [2] e0 4a [2] df 56 }

  condition:
    any of them
}