rule TTP_XOR_WriteProcessMemory_2418 {
  strings:
    $key_2418 = { 73 6a [2] 41 48 [2] 47 7d [2] 69 7d [2] 56 61 }

  condition:
    any of them
}