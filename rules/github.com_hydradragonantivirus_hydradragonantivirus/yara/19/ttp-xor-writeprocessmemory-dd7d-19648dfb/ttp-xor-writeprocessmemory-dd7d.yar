rule TTP_XOR_WriteProcessMemory_dd7d {
  strings:
    $key_dd7d = { 8a 0f [2] b8 2d [2] be 18 [2] 90 18 [2] af 04 }

  condition:
    any of them
}