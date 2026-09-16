rule TTP_XOR_WriteProcessMemory_06c8 {
  strings:
    $key_06c8 = { 51 ba [2] 63 98 [2] 65 ad [2] 4b ad [2] 74 b1 }

  condition:
    any of them
}