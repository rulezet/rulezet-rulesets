rule TTP_XOR_WriteProcessMemory_dcb9 {
  strings:
    $key_dcb9 = { 8b cb [2] b9 e9 [2] bf dc [2] 91 dc [2] ae c0 }

  condition:
    any of them
}