rule TTP_XOR_WriteProcessMemory_b218 {
  strings:
    $key_b218 = { e5 6a [2] d7 48 [2] d1 7d [2] ff 7d [2] c0 61 }

  condition:
    any of them
}