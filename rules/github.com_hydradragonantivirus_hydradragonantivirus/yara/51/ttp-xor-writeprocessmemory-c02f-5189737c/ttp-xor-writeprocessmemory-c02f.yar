rule TTP_XOR_WriteProcessMemory_c02f {
  strings:
    $key_c02f = { 97 5d [2] a5 7f [2] a3 4a [2] 8d 4a [2] b2 56 }

  condition:
    any of them
}