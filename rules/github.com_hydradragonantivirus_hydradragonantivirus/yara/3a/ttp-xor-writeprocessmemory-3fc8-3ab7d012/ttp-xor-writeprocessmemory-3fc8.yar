rule TTP_XOR_WriteProcessMemory_3fc8 {
  strings:
    $key_3fc8 = { 68 ba [2] 5a 98 [2] 5c ad [2] 72 ad [2] 4d b1 }

  condition:
    any of them
}