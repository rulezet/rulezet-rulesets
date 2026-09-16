rule TTP_XOR_WriteProcessMemory_ad6d {
  strings:
    $key_ad6d = { fa 1f [2] c8 3d [2] ce 08 [2] e0 08 [2] df 14 }

  condition:
    any of them
}