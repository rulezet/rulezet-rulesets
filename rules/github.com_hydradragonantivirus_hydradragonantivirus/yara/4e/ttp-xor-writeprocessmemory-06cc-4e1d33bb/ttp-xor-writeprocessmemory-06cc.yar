rule TTP_XOR_WriteProcessMemory_06cc {
  strings:
    $key_06cc = { 51 be [2] 63 9c [2] 65 a9 [2] 4b a9 [2] 74 b5 }

  condition:
    any of them
}