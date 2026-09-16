rule TTP_XOR_WriteProcessMemory_dd28 {
  strings:
    $key_dd28 = { 8a 5a [2] b8 78 [2] be 4d [2] 90 4d [2] af 51 }

  condition:
    any of them
}