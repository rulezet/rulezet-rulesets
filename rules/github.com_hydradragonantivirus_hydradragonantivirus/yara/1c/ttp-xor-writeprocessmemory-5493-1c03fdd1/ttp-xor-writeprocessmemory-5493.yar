rule TTP_XOR_WriteProcessMemory_5493 {
  strings:
    $key_5493 = { 03 e1 [2] 31 c3 [2] 37 f6 [2] 19 f6 [2] 26 ea }

  condition:
    any of them
}