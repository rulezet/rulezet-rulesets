rule TTP_XOR_WriteProcessMemory_d01a {
  strings:
    $key_d01a = { 87 68 [2] b5 4a [2] b3 7f [2] 9d 7f [2] a2 63 }

  condition:
    any of them
}