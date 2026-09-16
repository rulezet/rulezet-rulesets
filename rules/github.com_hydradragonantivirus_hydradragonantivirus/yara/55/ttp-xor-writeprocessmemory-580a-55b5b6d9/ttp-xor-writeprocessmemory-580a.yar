rule TTP_XOR_WriteProcessMemory_580a {
  strings:
    $key_580a = { 0f 78 [2] 3d 5a [2] 3b 6f [2] 15 6f [2] 2a 73 }

  condition:
    any of them
}