rule TTP_XOR_WriteProcessMemory_105f {
  strings:
    $key_105f = { 47 2d [2] 75 0f [2] 73 3a [2] 5d 3a [2] 62 26 }

  condition:
    any of them
}