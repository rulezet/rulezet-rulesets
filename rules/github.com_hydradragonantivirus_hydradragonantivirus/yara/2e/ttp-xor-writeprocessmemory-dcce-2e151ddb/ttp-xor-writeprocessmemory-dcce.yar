rule TTP_XOR_WriteProcessMemory_dcce {
  strings:
    $key_dcce = { 8b bc [2] b9 9e [2] bf ab [2] 91 ab [2] ae b7 }

  condition:
    any of them
}