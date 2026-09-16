rule TTP_XOR_WriteProcessMemory_0d10 {
  strings:
    $key_0d10 = { 5a 62 [2] 68 40 [2] 6e 75 [2] 40 75 [2] 7f 69 }

  condition:
    any of them
}