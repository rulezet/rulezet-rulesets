rule TTP_XOR_WriteProcessMemory_84fa {
  strings:
    $key_84fa = { d3 88 [2] e1 aa [2] e7 9f [2] c9 9f [2] f6 83 }

  condition:
    any of them
}