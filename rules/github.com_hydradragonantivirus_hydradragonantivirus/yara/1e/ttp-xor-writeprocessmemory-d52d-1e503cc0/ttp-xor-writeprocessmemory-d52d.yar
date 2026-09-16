rule TTP_XOR_WriteProcessMemory_d52d {
  strings:
    $key_d52d = { 82 5f [2] b0 7d [2] b6 48 [2] 98 48 [2] a7 54 }

  condition:
    any of them
}