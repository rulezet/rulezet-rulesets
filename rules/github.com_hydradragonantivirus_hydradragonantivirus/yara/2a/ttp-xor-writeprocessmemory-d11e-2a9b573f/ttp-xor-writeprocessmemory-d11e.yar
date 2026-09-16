rule TTP_XOR_WriteProcessMemory_d11e {
  strings:
    $key_d11e = { 86 6c [2] b4 4e [2] b2 7b [2] 9c 7b [2] a3 67 }

  condition:
    any of them
}