rule TTP_XOR_WriteProcessMemory_e304 {
  strings:
    $key_e304 = { b4 76 [2] 86 54 [2] 80 61 [2] ae 61 [2] 91 7d }

  condition:
    any of them
}