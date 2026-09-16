rule TTP_XOR_WriteProcessMemory_cc5b {
  strings:
    $key_cc5b = { 9b 29 [2] a9 0b [2] af 3e [2] 81 3e [2] be 22 }

  condition:
    any of them
}