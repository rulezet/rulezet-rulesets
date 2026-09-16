rule TTP_XOR_WriteProcessMemory_583f {
  strings:
    $key_583f = { 0f 4d [2] 3d 6f [2] 3b 5a [2] 15 5a [2] 2a 46 }

  condition:
    any of them
}