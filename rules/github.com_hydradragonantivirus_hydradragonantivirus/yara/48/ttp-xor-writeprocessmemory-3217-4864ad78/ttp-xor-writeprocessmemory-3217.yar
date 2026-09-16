rule TTP_XOR_WriteProcessMemory_3217 {
  strings:
    $key_3217 = { 65 65 [2] 57 47 [2] 51 72 [2] 7f 72 [2] 40 6e }

  condition:
    any of them
}