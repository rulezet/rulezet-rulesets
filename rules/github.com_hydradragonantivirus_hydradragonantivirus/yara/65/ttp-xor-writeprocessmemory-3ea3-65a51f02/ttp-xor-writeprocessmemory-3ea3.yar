rule TTP_XOR_WriteProcessMemory_3ea3 {
  strings:
    $key_3ea3 = { 69 d1 [2] 5b f3 [2] 5d c6 [2] 73 c6 [2] 4c da }

  condition:
    any of them
}