rule TTP_XOR_WriteProcessMemory_6617 {
  strings:
    $key_6617 = { 31 65 [2] 03 47 [2] 05 72 [2] 2b 72 [2] 14 6e }

  condition:
    any of them
}