rule TTP_XOR_WriteProcessMemory_587a {
  strings:
    $key_587a = { 0f 08 [2] 3d 2a [2] 3b 1f [2] 15 1f [2] 2a 03 }

  condition:
    any of them
}