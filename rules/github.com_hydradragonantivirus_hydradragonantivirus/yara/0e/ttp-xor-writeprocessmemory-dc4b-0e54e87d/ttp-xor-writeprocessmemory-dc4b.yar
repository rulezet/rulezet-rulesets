rule TTP_XOR_WriteProcessMemory_dc4b {
  strings:
    $key_dc4b = { 8b 39 [2] b9 1b [2] bf 2e [2] 91 2e [2] ae 32 }

  condition:
    any of them
}