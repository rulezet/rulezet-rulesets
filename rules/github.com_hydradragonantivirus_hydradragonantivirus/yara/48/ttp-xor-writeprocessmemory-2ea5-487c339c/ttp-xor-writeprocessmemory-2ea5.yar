rule TTP_XOR_WriteProcessMemory_2ea5 {
  strings:
    $key_2ea5 = { 79 d7 [2] 4b f5 [2] 4d c0 [2] 63 c0 [2] 5c dc }

  condition:
    any of them
}