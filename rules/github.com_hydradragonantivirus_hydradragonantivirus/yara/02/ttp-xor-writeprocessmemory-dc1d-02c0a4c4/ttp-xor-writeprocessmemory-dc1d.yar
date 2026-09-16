rule TTP_XOR_WriteProcessMemory_dc1d {
  strings:
    $key_dc1d = { 8b 6f [2] b9 4d [2] bf 78 [2] 91 78 [2] ae 64 }

  condition:
    any of them
}