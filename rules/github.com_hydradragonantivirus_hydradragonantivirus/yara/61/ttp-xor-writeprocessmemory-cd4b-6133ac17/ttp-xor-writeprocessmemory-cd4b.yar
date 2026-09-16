rule TTP_XOR_WriteProcessMemory_cd4b {
  strings:
    $key_cd4b = { 9a 39 [2] a8 1b [2] ae 2e [2] 80 2e [2] bf 32 }

  condition:
    any of them
}