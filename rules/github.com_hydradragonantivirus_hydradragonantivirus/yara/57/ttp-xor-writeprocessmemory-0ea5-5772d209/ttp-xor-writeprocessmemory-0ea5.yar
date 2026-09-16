rule TTP_XOR_WriteProcessMemory_0ea5 {
  strings:
    $key_0ea5 = { 59 d7 [2] 6b f5 [2] 6d c0 [2] 43 c0 [2] 7c dc }

  condition:
    any of them
}