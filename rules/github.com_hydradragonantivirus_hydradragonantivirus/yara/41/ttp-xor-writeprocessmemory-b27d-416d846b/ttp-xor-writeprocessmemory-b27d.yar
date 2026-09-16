rule TTP_XOR_WriteProcessMemory_b27d {
  strings:
    $key_b27d = { e5 0f [2] d7 2d [2] d1 18 [2] ff 18 [2] c0 04 }

  condition:
    any of them
}