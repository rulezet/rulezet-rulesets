rule TTP_XOR_WriteProcessMemory_c4fa {
  strings:
    $key_c4fa = { 93 88 [2] a1 aa [2] a7 9f [2] 89 9f [2] b6 83 }

  condition:
    any of them
}