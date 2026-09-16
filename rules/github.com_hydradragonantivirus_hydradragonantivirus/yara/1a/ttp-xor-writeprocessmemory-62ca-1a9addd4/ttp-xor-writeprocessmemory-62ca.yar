rule TTP_XOR_WriteProcessMemory_62ca {
  strings:
    $key_62ca = { 35 b8 [2] 07 9a [2] 01 af [2] 2f af [2] 10 b3 }

  condition:
    any of them
}