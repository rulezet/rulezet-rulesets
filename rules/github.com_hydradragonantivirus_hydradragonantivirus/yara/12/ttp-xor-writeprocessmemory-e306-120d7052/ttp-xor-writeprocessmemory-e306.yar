rule TTP_XOR_WriteProcessMemory_e306 {
  strings:
    $key_e306 = { b4 74 [2] 86 56 [2] 80 63 [2] ae 63 [2] 91 7f }

  condition:
    any of them
}