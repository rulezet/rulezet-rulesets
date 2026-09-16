rule TTP_XOR_WriteProcessMemory_3127 {
  strings:
    $key_3127 = { 66 55 [2] 54 77 [2] 52 42 [2] 7c 42 [2] 43 5e }

  condition:
    any of them
}