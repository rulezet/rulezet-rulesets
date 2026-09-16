rule TTP_XOR_WriteProcessMemory_4818 {
  strings:
    $key_4818 = { 1f 6a [2] 2d 48 [2] 2b 7d [2] 05 7d [2] 3a 61 }

  condition:
    any of them
}