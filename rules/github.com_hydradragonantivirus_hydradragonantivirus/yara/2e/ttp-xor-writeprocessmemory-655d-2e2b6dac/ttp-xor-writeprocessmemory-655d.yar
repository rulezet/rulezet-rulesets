rule TTP_XOR_WriteProcessMemory_655d {
  strings:
    $key_655d = { 32 2f [2] 00 0d [2] 06 38 [2] 28 38 [2] 17 24 }

  condition:
    any of them
}