rule TTP_XOR_WriteProcessMemory_ca7e {
  strings:
    $key_ca7e = { 9d 0c [2] af 2e [2] a9 1b [2] 87 1b [2] b8 07 }

  condition:
    any of them
}