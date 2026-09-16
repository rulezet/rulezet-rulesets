rule TTP_XOR_WriteProcessMemory_e557 {
  strings:
    $key_e557 = { b2 25 [2] 80 07 [2] 86 32 [2] a8 32 [2] 97 2e }

  condition:
    any of them
}