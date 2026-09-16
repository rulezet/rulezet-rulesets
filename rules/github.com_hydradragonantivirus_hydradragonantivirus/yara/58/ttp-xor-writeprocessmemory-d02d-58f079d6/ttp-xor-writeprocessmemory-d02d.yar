rule TTP_XOR_WriteProcessMemory_d02d {
  strings:
    $key_d02d = { 87 5f [2] b5 7d [2] b3 48 [2] 9d 48 [2] a2 54 }

  condition:
    any of them
}