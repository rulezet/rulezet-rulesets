rule TTP_XOR_WriteProcessMemory_b2fa {
  strings:
    $key_b2fa = { e5 88 [2] d7 aa [2] d1 9f [2] ff 9f [2] c0 83 }

  condition:
    any of them
}