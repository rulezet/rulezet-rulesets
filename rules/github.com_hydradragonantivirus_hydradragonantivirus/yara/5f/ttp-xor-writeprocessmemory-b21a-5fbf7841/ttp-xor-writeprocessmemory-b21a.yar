rule TTP_XOR_WriteProcessMemory_b21a {
  strings:
    $key_b21a = { e5 68 [2] d7 4a [2] d1 7f [2] ff 7f [2] c0 63 }

  condition:
    any of them
}