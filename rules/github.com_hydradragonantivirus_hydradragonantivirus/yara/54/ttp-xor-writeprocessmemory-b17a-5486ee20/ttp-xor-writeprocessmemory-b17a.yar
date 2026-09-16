rule TTP_XOR_WriteProcessMemory_b17a {
  strings:
    $key_b17a = { e6 08 [2] d4 2a [2] d2 1f [2] fc 1f [2] c3 03 }

  condition:
    any of them
}