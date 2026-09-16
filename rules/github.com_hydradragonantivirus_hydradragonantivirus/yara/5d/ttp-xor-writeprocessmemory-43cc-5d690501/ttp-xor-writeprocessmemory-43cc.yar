rule TTP_XOR_WriteProcessMemory_43cc {
  strings:
    $key_43cc = { 14 be [2] 26 9c [2] 20 a9 [2] 0e a9 [2] 31 b5 }

  condition:
    any of them
}