rule TTP_XOR_WriteProcessMemory_dd2d {
  strings:
    $key_dd2d = { 8a 5f [2] b8 7d [2] be 48 [2] 90 48 [2] af 54 }

  condition:
    any of them
}