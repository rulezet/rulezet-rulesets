rule TTP_XOR_WriteProcessMemory_ca2f {
  strings:
    $key_ca2f = { 9d 5d [2] af 7f [2] a9 4a [2] 87 4a [2] b8 56 }

  condition:
    any of them
}