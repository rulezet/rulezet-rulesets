rule TTP_XOR_WriteProcessMemory_55fd {
  strings:
    $key_55fd = { 02 8f [2] 30 ad [2] 36 98 [2] 18 98 [2] 27 84 }

  condition:
    any of them
}