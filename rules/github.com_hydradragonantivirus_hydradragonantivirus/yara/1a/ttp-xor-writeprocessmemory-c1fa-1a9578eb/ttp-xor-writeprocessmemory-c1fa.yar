rule TTP_XOR_WriteProcessMemory_c1fa {
  strings:
    $key_c1fa = { 96 88 [2] a4 aa [2] a2 9f [2] 8c 9f [2] b3 83 }

  condition:
    any of them
}