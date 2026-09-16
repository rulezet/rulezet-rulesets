rule TTP_XOR_WriteProcessMemory_165a {
  strings:
    $key_165a = { 41 28 [2] 73 0a [2] 75 3f [2] 5b 3f [2] 64 23 }

  condition:
    any of them
}