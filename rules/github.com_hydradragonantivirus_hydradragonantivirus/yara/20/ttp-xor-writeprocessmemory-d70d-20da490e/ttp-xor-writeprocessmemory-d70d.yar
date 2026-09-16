rule TTP_XOR_WriteProcessMemory_d70d {
  strings:
    $key_d70d = { 80 7f [2] b2 5d [2] b4 68 [2] 9a 68 [2] a5 74 }

  condition:
    any of them
}