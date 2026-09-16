rule TTP_XOR_WriteProcessMemory_5217 {
  strings:
    $key_5217 = { 05 65 [2] 37 47 [2] 31 72 [2] 1f 72 [2] 20 6e }

  condition:
    any of them
}