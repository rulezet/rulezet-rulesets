rule TTP_XOR_WriteProcessMemory_34f4 {
  strings:
    $key_34f4 = { 63 86 [2] 51 a4 [2] 57 91 [2] 79 91 [2] 46 8d }

  condition:
    any of them
}