rule TTP_XOR_WriteProcessMemory_dcdc {
  strings:
    $key_dcdc = { 8b ae [2] b9 8c [2] bf b9 [2] 91 b9 [2] ae a5 }

  condition:
    any of them
}