rule TTP_XOR_WriteProcessMemory_3340 {
  strings:
    $key_3340 = { 64 32 [2] 56 10 [2] 50 25 [2] 7e 25 [2] 41 39 }

  condition:
    any of them
}