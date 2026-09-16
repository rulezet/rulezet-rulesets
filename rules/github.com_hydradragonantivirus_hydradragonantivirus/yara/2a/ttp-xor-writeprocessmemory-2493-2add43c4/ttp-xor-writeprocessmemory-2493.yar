rule TTP_XOR_WriteProcessMemory_2493 {
  strings:
    $key_2493 = { 73 e1 [2] 41 c3 [2] 47 f6 [2] 69 f6 [2] 56 ea }

  condition:
    any of them
}