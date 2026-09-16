rule TTP_XOR_WriteProcessMemory_56f4 {
  strings:
    $key_56f4 = { 01 86 [2] 33 a4 [2] 35 91 [2] 1b 91 [2] 24 8d }

  condition:
    any of them
}