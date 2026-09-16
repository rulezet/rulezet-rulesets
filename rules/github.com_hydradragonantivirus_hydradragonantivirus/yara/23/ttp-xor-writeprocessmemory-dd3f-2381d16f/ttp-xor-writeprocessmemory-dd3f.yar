rule TTP_XOR_WriteProcessMemory_dd3f {
  strings:
    $key_dd3f = { 8a 4d [2] b8 6f [2] be 5a [2] 90 5a [2] af 46 }

  condition:
    any of them
}