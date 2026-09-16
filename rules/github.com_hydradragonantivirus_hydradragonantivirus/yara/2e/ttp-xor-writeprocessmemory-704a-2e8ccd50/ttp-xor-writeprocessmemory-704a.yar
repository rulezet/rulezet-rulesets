rule TTP_XOR_WriteProcessMemory_704a {
  strings:
    $key_704a = { 27 38 [2] 15 1a [2] 13 2f [2] 3d 2f [2] 02 33 }

  condition:
    any of them
}