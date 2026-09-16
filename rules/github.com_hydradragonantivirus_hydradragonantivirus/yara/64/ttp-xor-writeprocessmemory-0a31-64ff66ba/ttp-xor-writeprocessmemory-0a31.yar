rule TTP_XOR_WriteProcessMemory_0a31 {
  strings:
    $key_0a31 = { 5d 43 [2] 6f 61 [2] 69 54 [2] 47 54 [2] 78 48 }

  condition:
    any of them
}