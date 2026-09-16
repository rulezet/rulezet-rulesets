rule TTP_XOR_WriteProcessMemory_aa3f {
  strings:
    $key_aa3f = { fd 4d [2] cf 6f [2] c9 5a [2] e7 5a [2] d8 46 }

  condition:
    any of them
}