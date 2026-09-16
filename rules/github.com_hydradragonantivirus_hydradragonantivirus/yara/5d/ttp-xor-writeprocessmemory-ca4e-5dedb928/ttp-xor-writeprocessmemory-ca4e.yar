rule TTP_XOR_WriteProcessMemory_ca4e {
  strings:
    $key_ca4e = { 9d 3c [2] af 1e [2] a9 2b [2] 87 2b [2] b8 37 }

  condition:
    any of them
}