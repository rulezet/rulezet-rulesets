rule TTP_XOR_WriteProcessMemory_23f4 {
  strings:
    $key_23f4 = { 74 86 [2] 46 a4 [2] 40 91 [2] 6e 91 [2] 51 8d }

  condition:
    any of them
}