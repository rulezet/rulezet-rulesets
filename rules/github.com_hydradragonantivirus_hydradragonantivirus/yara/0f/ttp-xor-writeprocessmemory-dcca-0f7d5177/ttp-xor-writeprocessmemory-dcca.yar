rule TTP_XOR_WriteProcessMemory_dcca {
  strings:
    $key_dcca = { 8b b8 [2] b9 9a [2] bf af [2] 91 af [2] ae b3 }

  condition:
    any of them
}