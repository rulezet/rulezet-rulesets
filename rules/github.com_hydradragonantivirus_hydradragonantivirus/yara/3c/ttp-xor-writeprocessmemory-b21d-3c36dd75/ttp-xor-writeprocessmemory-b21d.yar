rule TTP_XOR_WriteProcessMemory_b21d {
  strings:
    $key_b21d = { e5 6f [2] d7 4d [2] d1 78 [2] ff 78 [2] c0 64 }

  condition:
    any of them
}