rule TTP_XOR_WriteProcessMemory_dd4a {
  strings:
    $key_dd4a = { 8a 38 [2] b8 1a [2] be 2f [2] 90 2f [2] af 33 }

  condition:
    any of them
}