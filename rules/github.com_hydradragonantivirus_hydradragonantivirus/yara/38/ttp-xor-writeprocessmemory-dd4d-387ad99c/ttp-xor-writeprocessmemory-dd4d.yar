rule TTP_XOR_WriteProcessMemory_dd4d {
  strings:
    $key_dd4d = { 8a 3f [2] b8 1d [2] be 28 [2] 90 28 [2] af 34 }

  condition:
    any of them
}