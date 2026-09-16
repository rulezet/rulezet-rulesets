rule TTP_XOR_WriteProcessMemory_e2fa {
  strings:
    $key_e2fa = { b5 88 [2] 87 aa [2] 81 9f [2] af 9f [2] 90 83 }

  condition:
    any of them
}