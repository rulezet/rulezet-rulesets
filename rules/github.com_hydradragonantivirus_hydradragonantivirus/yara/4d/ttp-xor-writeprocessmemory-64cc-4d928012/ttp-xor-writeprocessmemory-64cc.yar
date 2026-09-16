rule TTP_XOR_WriteProcessMemory_64cc {
  strings:
    $key_64cc = { 33 be [2] 01 9c [2] 07 a9 [2] 29 a9 [2] 16 b5 }

  condition:
    any of them
}