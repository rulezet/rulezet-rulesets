rule TTP_XOR_WriteProcessMemory_1693 {
  strings:
    $key_1693 = { 41 e1 [2] 73 c3 [2] 75 f6 [2] 5b f6 [2] 64 ea }

  condition:
    any of them
}