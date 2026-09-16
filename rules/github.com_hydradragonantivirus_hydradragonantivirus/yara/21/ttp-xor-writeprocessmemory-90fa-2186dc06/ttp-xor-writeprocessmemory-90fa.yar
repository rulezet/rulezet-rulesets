rule TTP_XOR_WriteProcessMemory_90fa {
  strings:
    $key_90fa = { c7 88 [2] f5 aa [2] f3 9f [2] dd 9f [2] e2 83 }

  condition:
    any of them
}