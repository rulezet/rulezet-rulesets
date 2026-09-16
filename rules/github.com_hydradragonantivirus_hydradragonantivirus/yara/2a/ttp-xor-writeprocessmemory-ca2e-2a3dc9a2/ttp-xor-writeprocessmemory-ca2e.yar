rule TTP_XOR_WriteProcessMemory_ca2e {
  strings:
    $key_ca2e = { 9d 5c [2] af 7e [2] a9 4b [2] 87 4b [2] b8 57 }

  condition:
    any of them
}