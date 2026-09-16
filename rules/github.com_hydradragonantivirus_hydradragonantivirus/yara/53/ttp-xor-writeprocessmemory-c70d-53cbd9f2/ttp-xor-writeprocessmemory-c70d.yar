rule TTP_XOR_WriteProcessMemory_c70d {
  strings:
    $key_c70d = { 90 7f [2] a2 5d [2] a4 68 [2] 8a 68 [2] b5 74 }

  condition:
    any of them
}