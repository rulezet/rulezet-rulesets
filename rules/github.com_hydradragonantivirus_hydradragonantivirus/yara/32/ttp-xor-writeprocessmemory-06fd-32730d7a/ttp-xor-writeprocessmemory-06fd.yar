rule TTP_XOR_WriteProcessMemory_06fd {
  strings:
    $key_06fd = { 51 8f [2] 63 ad [2] 65 98 [2] 4b 98 [2] 74 84 }

  condition:
    any of them
}