rule TTP_XOR_WriteProcessMemory_00ea {
  strings:
    $key_00ea = { 57 98 [2] 65 ba [2] 63 8f [2] 4d 8f [2] 72 93 }

  condition:
    any of them
}