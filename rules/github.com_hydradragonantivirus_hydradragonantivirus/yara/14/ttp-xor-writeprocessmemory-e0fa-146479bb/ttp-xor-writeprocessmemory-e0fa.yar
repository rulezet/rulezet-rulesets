rule TTP_XOR_WriteProcessMemory_e0fa {
  strings:
    $key_e0fa = { b7 88 [2] 85 aa [2] 83 9f [2] ad 9f [2] 92 83 }

  condition:
    any of them
}