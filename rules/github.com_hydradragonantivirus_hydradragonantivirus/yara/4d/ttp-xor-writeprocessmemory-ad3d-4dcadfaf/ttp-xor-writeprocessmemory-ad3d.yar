rule TTP_XOR_WriteProcessMemory_ad3d {
  strings:
    $key_ad3d = { fa 4f [2] c8 6d [2] ce 58 [2] e0 58 [2] df 44 }

  condition:
    any of them
}