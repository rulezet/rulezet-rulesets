rule TTP_XOR_WriteProcessMemory_d41a {
  strings:
    $key_d41a = { 83 68 [2] b1 4a [2] b7 7f [2] 99 7f [2] a6 63 }

  condition:
    any of them
}