rule TTP_XOR_WriteProcessMemory_00fd {
  strings:
    $key_00fd = { 57 8f [2] 65 ad [2] 63 98 [2] 4d 98 [2] 72 84 }

  condition:
    any of them
}