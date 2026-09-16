rule TTP_XOR_WriteProcessMemory_6894 {
  strings:
    $key_6894 = { 3f e6 [2] 0d c4 [2] 0b f1 [2] 25 f1 [2] 1a ed }

  condition:
    any of them
}