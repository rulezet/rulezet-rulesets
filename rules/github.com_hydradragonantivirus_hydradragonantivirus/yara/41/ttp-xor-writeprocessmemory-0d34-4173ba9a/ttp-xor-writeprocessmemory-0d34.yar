rule TTP_XOR_WriteProcessMemory_0d34 {
  strings:
    $key_0d34 = { 5a 46 [2] 68 64 [2] 6e 51 [2] 40 51 [2] 7f 4d }

  condition:
    any of them
}