rule TTP_XOR_WriteProcessMemory_00dd {
  strings:
    $key_00dd = { 57 af [2] 65 8d [2] 63 b8 [2] 4d b8 [2] 72 a4 }

  condition:
    any of them
}