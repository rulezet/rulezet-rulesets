rule TTP_XOR_WriteProcessMemory_ca4d {
  strings:
    $key_ca4d = { 9d 3f [2] af 1d [2] a9 28 [2] 87 28 [2] b8 34 }

  condition:
    any of them
}