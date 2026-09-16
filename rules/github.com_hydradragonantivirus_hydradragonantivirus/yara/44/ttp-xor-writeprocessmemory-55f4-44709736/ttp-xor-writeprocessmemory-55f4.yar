rule TTP_XOR_WriteProcessMemory_55f4 {
  strings:
    $key_55f4 = { 02 86 [2] 30 a4 [2] 36 91 [2] 18 91 [2] 27 8d }

  condition:
    any of them
}