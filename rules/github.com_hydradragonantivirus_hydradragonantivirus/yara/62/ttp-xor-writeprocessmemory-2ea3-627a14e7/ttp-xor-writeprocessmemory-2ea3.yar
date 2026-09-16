rule TTP_XOR_WriteProcessMemory_2ea3 {
  strings:
    $key_2ea3 = { 79 d1 [2] 4b f3 [2] 4d c6 [2] 63 c6 [2] 5c da }

  condition:
    any of them
}