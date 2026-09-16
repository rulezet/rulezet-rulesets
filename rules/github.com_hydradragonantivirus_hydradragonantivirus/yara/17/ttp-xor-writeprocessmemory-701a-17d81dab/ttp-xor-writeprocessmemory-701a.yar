rule TTP_XOR_WriteProcessMemory_701a {
  strings:
    $key_701a = { 27 68 [2] 15 4a [2] 13 7f [2] 3d 7f [2] 02 63 }

  condition:
    any of them
}