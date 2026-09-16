rule TTP_XOR_WriteProcessMemory_ce95 {
  strings:
    $key_ce95 = { 99 e7 [2] ab c5 [2] ad f0 [2] 83 f0 [2] bc ec }

  condition:
    any of them
}