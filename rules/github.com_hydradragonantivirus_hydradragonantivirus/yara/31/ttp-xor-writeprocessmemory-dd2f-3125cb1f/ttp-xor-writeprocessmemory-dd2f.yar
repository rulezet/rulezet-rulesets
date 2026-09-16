rule TTP_XOR_WriteProcessMemory_dd2f {
  strings:
    $key_dd2f = { 8a 5d [2] b8 7f [2] be 4a [2] 90 4a [2] af 56 }

  condition:
    any of them
}