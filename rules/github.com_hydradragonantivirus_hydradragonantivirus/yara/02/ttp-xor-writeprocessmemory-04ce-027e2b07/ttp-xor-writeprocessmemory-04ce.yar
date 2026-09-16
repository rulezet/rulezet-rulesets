rule TTP_XOR_WriteProcessMemory_04ce {
  strings:
    $key_04ce = { 53 bc [2] 61 9e [2] 67 ab [2] 49 ab [2] 76 b7 }

  condition:
    any of them
}