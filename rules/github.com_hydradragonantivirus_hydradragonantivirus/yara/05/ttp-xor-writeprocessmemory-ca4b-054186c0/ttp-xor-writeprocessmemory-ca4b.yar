rule TTP_XOR_WriteProcessMemory_ca4b {
  strings:
    $key_ca4b = { 9d 39 [2] af 1b [2] a9 2e [2] 87 2e [2] b8 32 }

  condition:
    any of them
}