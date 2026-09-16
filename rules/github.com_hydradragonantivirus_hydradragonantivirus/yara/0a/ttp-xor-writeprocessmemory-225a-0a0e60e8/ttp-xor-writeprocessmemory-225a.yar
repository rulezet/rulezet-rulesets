rule TTP_XOR_WriteProcessMemory_225a {
  strings:
    $key_225a = { 75 28 [2] 47 0a [2] 41 3f [2] 6f 3f [2] 50 23 }

  condition:
    any of them
}