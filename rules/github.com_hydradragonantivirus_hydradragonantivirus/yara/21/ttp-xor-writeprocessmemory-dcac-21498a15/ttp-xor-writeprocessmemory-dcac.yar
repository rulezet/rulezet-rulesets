rule TTP_XOR_WriteProcessMemory_dcac {
  strings:
    $key_dcac = { 8b de [2] b9 fc [2] bf c9 [2] 91 c9 [2] ae d5 }

  condition:
    any of them
}