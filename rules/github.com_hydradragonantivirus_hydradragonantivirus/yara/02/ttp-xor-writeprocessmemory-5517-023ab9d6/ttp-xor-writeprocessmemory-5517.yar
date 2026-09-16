rule TTP_XOR_WriteProcessMemory_5517 {
  strings:
    $key_5517 = { 02 65 [2] 30 47 [2] 36 72 [2] 18 72 [2] 27 6e }

  condition:
    any of them
}