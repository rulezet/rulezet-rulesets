rule TTP_XOR_WriteProcessMemory_e22d {
  strings:
    $key_e22d = { b5 5f [2] 87 7d [2] 81 48 [2] af 48 [2] 90 54 }

  condition:
    any of them
}