rule TTP_XOR_WriteProcessMemory_cea8 {
  strings:
    $key_cea8 = { 99 da [2] ab f8 [2] ad cd [2] 83 cd [2] bc d1 }

  condition:
    any of them
}