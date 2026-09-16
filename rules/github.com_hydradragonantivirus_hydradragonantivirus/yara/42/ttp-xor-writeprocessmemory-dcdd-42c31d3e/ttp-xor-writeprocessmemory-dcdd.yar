rule TTP_XOR_WriteProcessMemory_dcdd {
  strings:
    $key_dcdd = { 8b af [2] b9 8d [2] bf b8 [2] 91 b8 [2] ae a4 }

  condition:
    any of them
}