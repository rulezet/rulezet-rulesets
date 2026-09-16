rule TTP_XOR_WriteProcessMemory_e6fa {
  strings:
    $key_e6fa = { b1 88 [2] 83 aa [2] 85 9f [2] ab 9f [2] 94 83 }

  condition:
    any of them
}