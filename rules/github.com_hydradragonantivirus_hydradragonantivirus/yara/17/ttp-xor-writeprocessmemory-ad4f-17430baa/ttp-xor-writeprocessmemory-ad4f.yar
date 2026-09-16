rule TTP_XOR_WriteProcessMemory_ad4f {
  strings:
    $key_ad4f = { fa 3d [2] c8 1f [2] ce 2a [2] e0 2a [2] df 36 }

  condition:
    any of them
}