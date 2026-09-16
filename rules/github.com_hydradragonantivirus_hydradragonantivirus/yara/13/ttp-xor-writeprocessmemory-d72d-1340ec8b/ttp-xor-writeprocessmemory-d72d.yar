rule TTP_XOR_WriteProcessMemory_d72d {
  strings:
    $key_d72d = { 80 5f [2] b2 7d [2] b4 48 [2] 9a 48 [2] a5 54 }

  condition:
    any of them
}