rule TTP_XOR_WriteProcessMemory_d5fa {
  strings:
    $key_d5fa = { 82 88 [2] b0 aa [2] b6 9f [2] 98 9f [2] a7 83 }

  condition:
    any of them
}