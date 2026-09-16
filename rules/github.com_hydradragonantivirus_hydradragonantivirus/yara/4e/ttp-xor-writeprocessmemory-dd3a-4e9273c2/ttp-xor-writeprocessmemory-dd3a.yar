rule TTP_XOR_WriteProcessMemory_dd3a {
  strings:
    $key_dd3a = { 8a 48 [2] b8 6a [2] be 5f [2] 90 5f [2] af 43 }

  condition:
    any of them
}