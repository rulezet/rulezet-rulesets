rule TTP_XOR_WriteProcessMemory_2482 {
  strings:
    $key_2482 = { 73 f0 [2] 41 d2 [2] 47 e7 [2] 69 e7 [2] 56 fb }

  condition:
    any of them
}