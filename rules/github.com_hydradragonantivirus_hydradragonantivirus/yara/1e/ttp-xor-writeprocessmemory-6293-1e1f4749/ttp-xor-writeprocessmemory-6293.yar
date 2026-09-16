rule TTP_XOR_WriteProcessMemory_6293 {
  strings:
    $key_6293 = { 35 e1 [2] 07 c3 [2] 01 f6 [2] 2f f6 [2] 10 ea }

  condition:
    any of them
}