rule TTP_XOR_WriteProcessMemory_d10d {
  strings:
    $key_d10d = { 86 7f [2] b4 5d [2] b2 68 [2] 9c 68 [2] a3 74 }

  condition:
    any of them
}