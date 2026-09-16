rule TTP_XOR_WriteProcessMemory_0d31 {
  strings:
    $key_0d31 = { 5a 43 [2] 68 61 [2] 6e 54 [2] 40 54 [2] 7f 48 }

  condition:
    any of them
}