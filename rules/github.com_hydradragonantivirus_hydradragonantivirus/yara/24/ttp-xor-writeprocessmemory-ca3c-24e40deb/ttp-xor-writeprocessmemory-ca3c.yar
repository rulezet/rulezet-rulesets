rule TTP_XOR_WriteProcessMemory_ca3c {
  strings:
    $key_ca3c = { 9d 4e [2] af 6c [2] a9 59 [2] 87 59 [2] b8 45 }

  condition:
    any of them
}