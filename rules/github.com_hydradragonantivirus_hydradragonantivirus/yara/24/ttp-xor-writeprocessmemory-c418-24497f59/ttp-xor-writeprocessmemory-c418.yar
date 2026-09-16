rule TTP_XOR_WriteProcessMemory_c418 {
  strings:
    $key_c418 = { 93 6a [2] a1 48 [2] a7 7d [2] 89 7d [2] b6 61 }

  condition:
    any of them
}