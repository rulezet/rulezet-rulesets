rule TTP_XOR_WriteProcessMemory_72ca {
  strings:
    $key_72ca = { 25 b8 [2] 17 9a [2] 11 af [2] 3f af [2] 00 b3 }

  condition:
    any of them
}