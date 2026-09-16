rule TTP_XOR_WriteProcessMemory_e376 {
  strings:
    $key_e376 = { b4 04 [2] 86 26 [2] 80 13 [2] ae 13 [2] 91 0f }

  condition:
    any of them
}