rule TTP_XOR_WriteProcessMemory_0622 {
  strings:
    $key_0622 = { 51 50 [2] 63 72 [2] 65 47 [2] 4b 47 [2] 74 5b }

  condition:
    any of them
}