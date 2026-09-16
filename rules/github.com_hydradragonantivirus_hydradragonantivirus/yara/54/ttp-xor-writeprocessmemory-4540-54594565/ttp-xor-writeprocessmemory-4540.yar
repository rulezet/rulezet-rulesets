rule TTP_XOR_WriteProcessMemory_4540 {
  strings:
    $key_4540 = { 12 32 [2] 20 10 [2] 26 25 [2] 08 25 [2] 37 39 }

  condition:
    any of them
}