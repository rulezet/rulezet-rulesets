rule TTP_XOR_WriteProcessMemory_c00d {
  strings:
    $key_c00d = { 97 7f [2] a5 5d [2] a3 68 [2] 8d 68 [2] b2 74 }

  condition:
    any of them
}