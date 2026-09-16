rule TTP_XOR_WriteProcessMemory_0d33 {
  strings:
    $key_0d33 = { 5a 41 [2] 68 63 [2] 6e 56 [2] 40 56 [2] 7f 4a }

  condition:
    any of them
}