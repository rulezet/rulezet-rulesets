rule TTP_XOR_WriteProcessMemory_d4fa {
  strings:
    $key_d4fa = { 83 88 [2] b1 aa [2] b7 9f [2] 99 9f [2] a6 83 }

  condition:
    any of them
}