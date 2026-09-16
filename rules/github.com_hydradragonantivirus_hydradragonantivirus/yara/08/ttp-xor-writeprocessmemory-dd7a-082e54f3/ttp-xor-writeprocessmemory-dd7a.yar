rule TTP_XOR_WriteProcessMemory_dd7a {
  strings:
    $key_dd7a = { 8a 08 [2] b8 2a [2] be 1f [2] 90 1f [2] af 03 }

  condition:
    any of them
}