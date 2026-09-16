rule TTP_XOR_WriteProcessMemory_ca18 {
  strings:
    $key_ca18 = { 9d 6a [2] af 48 [2] a9 7d [2] 87 7d [2] b8 61 }

  condition:
    any of them
}