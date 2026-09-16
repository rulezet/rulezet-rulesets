rule TTP_XOR_WriteProcessMemory_046f {
  strings:
    $key_046f = { 53 1d [2] 61 3f [2] 67 0a [2] 49 0a [2] 76 16 }

  condition:
    any of them
}