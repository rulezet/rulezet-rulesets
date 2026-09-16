rule TTP_XOR_WriteProcessMemory_5a31 {
  strings:
    $key_5a31 = { 0d 43 [2] 3f 61 [2] 39 54 [2] 17 54 [2] 28 48 }

  condition:
    any of them
}