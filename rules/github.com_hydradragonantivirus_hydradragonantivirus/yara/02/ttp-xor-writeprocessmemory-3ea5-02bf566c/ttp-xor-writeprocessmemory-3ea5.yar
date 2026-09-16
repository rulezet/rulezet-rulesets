rule TTP_XOR_WriteProcessMemory_3ea5 {
  strings:
    $key_3ea5 = { 69 d7 [2] 5b f5 [2] 5d c0 [2] 73 c0 [2] 4c dc }

  condition:
    any of them
}