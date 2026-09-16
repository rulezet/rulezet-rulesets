rule TTP_XOR_WriteProcessMemory_dd2a {
  strings:
    $key_dd2a = { 8a 58 [2] b8 7a [2] be 4f [2] 90 4f [2] af 53 }

  condition:
    any of them
}