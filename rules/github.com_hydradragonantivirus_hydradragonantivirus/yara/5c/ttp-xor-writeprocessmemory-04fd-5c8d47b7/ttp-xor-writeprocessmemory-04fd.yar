rule TTP_XOR_WriteProcessMemory_04fd {
  strings:
    $key_04fd = { 53 8f [2] 61 ad [2] 67 98 [2] 49 98 [2] 76 84 }

  condition:
    any of them
}