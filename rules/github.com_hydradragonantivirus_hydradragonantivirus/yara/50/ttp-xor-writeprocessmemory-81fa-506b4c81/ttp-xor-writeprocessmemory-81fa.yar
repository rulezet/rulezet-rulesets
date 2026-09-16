rule TTP_XOR_WriteProcessMemory_81fa {
  strings:
    $key_81fa = { d6 88 [2] e4 aa [2] e2 9f [2] cc 9f [2] f3 83 }

  condition:
    any of them
}