rule TTP_XOR_WriteProcessMemory_b7fa {
  strings:
    $key_b7fa = { e0 88 [2] d2 aa [2] d4 9f [2] fa 9f [2] c5 83 }

  condition:
    any of them
}