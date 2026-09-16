rule TTP_XOR_WriteProcessMemory_ca1c {
  strings:
    $key_ca1c = { 9d 6e [2] af 4c [2] a9 79 [2] 87 79 [2] b8 65 }

  condition:
    any of them
}