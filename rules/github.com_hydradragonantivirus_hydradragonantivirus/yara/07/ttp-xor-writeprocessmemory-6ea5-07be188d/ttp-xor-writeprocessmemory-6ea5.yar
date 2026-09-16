rule TTP_XOR_WriteProcessMemory_6ea5 {
  strings:
    $key_6ea5 = { 39 d7 [2] 0b f5 [2] 0d c0 [2] 23 c0 [2] 1c dc }

  condition:
    any of them
}