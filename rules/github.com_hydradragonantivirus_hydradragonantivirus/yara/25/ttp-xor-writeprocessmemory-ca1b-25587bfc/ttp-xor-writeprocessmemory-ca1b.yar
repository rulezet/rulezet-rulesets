rule TTP_XOR_WriteProcessMemory_ca1b {
  strings:
    $key_ca1b = { 9d 69 [2] af 4b [2] a9 7e [2] 87 7e [2] b8 62 }

  condition:
    any of them
}