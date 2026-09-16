rule TTP_XOR_WriteProcessMemory_ffdf {
  strings:
    $key_ffdf = { a8 ad [2] 9a 8f [2] 9c ba [2] b2 ba [2] 8d a6 }

  condition:
    any of them
}