rule TTP_XOR_WriteProcessMemory_dc57 {
  strings:
    $key_dc57 = { 8b 25 [2] b9 07 [2] bf 32 [2] 91 32 [2] ae 2e }

  condition:
    any of them
}