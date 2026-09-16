rule TTP_XOR_WriteProcessMemory_7fc1 {
  strings:
    $key_7fc1 = { 28 b3 [2] 1a 91 [2] 1c a4 [2] 32 a4 [2] 0d b8 }

  condition:
    any of them
}