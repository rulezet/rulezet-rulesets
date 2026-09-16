rule TTP_XOR_WriteProcessMemory_0e31 {
  strings:
    $key_0e31 = { 59 43 [2] 6b 61 [2] 6d 54 [2] 43 54 [2] 7c 48 }

  condition:
    any of them
}