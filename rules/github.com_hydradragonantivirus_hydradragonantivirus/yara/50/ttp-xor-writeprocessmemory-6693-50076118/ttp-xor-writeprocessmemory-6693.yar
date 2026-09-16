rule TTP_XOR_WriteProcessMemory_6693 {
  strings:
    $key_6693 = { 31 e1 [2] 03 c3 [2] 05 f6 [2] 2b f6 [2] 14 ea }

  condition:
    any of them
}