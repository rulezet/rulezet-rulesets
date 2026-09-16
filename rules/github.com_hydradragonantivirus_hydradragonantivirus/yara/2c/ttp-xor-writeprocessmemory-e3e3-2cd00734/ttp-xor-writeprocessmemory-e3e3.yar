rule TTP_XOR_WriteProcessMemory_e3e3 {
  strings:
    $key_e3e3 = { b4 91 [2] 86 b3 [2] 80 86 [2] ae 86 [2] 91 9a }

  condition:
    any of them
}