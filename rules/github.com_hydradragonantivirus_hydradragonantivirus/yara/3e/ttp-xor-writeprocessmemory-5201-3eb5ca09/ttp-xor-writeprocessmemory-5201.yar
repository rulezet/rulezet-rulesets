rule TTP_XOR_WriteProcessMemory_5201 {
  strings:
    $key_5201 = { 05 73 [2] 37 51 [2] 31 64 [2] 1f 64 [2] 20 78 }

  condition:
    any of them
}