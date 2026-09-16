rule TTP_XOR_WriteProcessMemory_45fd {
  strings:
    $key_45fd = { 12 8f [2] 20 ad [2] 26 98 [2] 08 98 [2] 37 84 }

  condition:
    any of them
}