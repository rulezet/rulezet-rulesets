rule TTP_XOR_WriteProcessMemory_54fd {
  strings:
    $key_54fd = { 03 8f [2] 31 ad [2] 37 98 [2] 19 98 [2] 26 84 }

  condition:
    any of them
}