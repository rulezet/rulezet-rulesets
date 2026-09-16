rule TTP_XOR_WriteProcessMemory_c8fd {
  strings:
    $key_c8fd = { 9f 8f [2] ad ad [2] ab 98 [2] 85 98 [2] ba 84 }

  condition:
    any of them
}