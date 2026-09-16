rule TTP_XOR_WriteProcessMemory_b20a {
  strings:
    $key_b20a = { e5 78 [2] d7 5a [2] d1 6f [2] ff 6f [2] c0 73 }

  condition:
    any of them
}