rule TTP_XOR_WriteProcessMemory_0d04 {
  strings:
    $key_0d04 = { 5a 76 [2] 68 54 [2] 6e 61 [2] 40 61 [2] 7f 7d }

  condition:
    any of them
}