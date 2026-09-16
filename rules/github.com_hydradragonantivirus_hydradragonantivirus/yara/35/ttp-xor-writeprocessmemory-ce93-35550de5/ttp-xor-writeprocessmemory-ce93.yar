rule TTP_XOR_WriteProcessMemory_ce93 {
  strings:
    $key_ce93 = { 99 e1 [2] ab c3 [2] ad f6 [2] 83 f6 [2] bc ea }

  condition:
    any of them
}