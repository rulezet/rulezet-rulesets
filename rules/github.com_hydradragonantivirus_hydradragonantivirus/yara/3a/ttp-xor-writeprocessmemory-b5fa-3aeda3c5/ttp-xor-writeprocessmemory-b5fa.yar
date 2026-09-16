rule TTP_XOR_WriteProcessMemory_b5fa {
  strings:
    $key_b5fa = { e2 88 [2] d0 aa [2] d6 9f [2] f8 9f [2] c7 83 }

  condition:
    any of them
}