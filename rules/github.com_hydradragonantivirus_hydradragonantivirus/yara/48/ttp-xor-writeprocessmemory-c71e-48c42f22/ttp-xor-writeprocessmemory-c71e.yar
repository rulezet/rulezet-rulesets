rule TTP_XOR_WriteProcessMemory_c71e {
  strings:
    $key_c71e = { 90 6c [2] a2 4e [2] a4 7b [2] 8a 7b [2] b5 67 }

  condition:
    any of them
}