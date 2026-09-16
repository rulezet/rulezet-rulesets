rule TTP_XOR_WriteProcessMemory_941a {
  strings:
    $key_941a = { c3 68 [2] f1 4a [2] f7 7f [2] d9 7f [2] e6 63 }

  condition:
    any of them
}