rule TTP_XOR_WriteProcessMemory_6d11 {
  strings:
    $key_6d11 = { 3a 63 [2] 08 41 [2] 0e 74 [2] 20 74 [2] 1f 68 }

  condition:
    any of them
}