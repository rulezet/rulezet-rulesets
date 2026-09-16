rule TTP_XOR_WriteProcessMemory_b70a {
  strings:
    $key_b70a = { e0 78 [2] d2 5a [2] d4 6f [2] fa 6f [2] c5 73 }

  condition:
    any of them
}