rule TTP_XOR_WriteProcessMemory_dd38 {
  strings:
    $key_dd38 = { 8a 4a [2] b8 68 [2] be 5d [2] 90 5d [2] af 41 }

  condition:
    any of them
}