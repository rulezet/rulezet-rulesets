rule TTP_XOR_WriteProcessMemory_ca48 {
  strings:
    $key_ca48 = { 9d 3a [2] af 18 [2] a9 2d [2] 87 2d [2] b8 31 }

  condition:
    any of them
}