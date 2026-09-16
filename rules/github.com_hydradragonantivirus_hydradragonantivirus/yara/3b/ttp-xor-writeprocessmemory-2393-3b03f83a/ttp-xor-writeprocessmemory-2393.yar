rule TTP_XOR_WriteProcessMemory_2393 {
  strings:
    $key_2393 = { 74 e1 [2] 46 c3 [2] 40 f6 [2] 6e f6 [2] 51 ea }

  condition:
    any of them
}