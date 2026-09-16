rule TTP_XOR_WriteProcessMemory_8439 {
  strings:
    $key_8439 = { d3 4b [2] e1 69 [2] e7 5c [2] c9 5c [2] f6 40 }

  condition:
    any of them
}