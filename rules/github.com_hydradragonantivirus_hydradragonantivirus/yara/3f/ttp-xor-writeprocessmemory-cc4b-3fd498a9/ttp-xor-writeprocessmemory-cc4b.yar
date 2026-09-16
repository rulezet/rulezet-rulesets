rule TTP_XOR_WriteProcessMemory_cc4b {
  strings:
    $key_cc4b = { 9b 39 [2] a9 1b [2] af 2e [2] 81 2e [2] be 32 }

  condition:
    any of them
}