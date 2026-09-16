rule TTP_XOR_WriteProcessMemory_0534 {
  strings:
    $key_0534 = { 52 46 [2] 60 64 [2] 66 51 [2] 48 51 [2] 77 4d }

  condition:
    any of them
}