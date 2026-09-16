rule TTP_XOR_WriteProcessMemory_33e3 {
  strings:
    $key_33e3 = { 64 91 [2] 56 b3 [2] 50 86 [2] 7e 86 [2] 41 9a }

  condition:
    any of them
}