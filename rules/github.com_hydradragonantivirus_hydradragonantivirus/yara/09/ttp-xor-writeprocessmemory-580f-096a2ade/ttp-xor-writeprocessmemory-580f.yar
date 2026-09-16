rule TTP_XOR_WriteProcessMemory_580f {
  strings:
    $key_580f = { 0f 7d [2] 3d 5f [2] 3b 6a [2] 15 6a [2] 2a 76 }

  condition:
    any of them
}