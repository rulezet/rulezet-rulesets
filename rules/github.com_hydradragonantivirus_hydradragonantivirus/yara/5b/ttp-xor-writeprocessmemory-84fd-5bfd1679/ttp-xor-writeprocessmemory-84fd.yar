rule TTP_XOR_WriteProcessMemory_84fd {
  strings:
    $key_84fd = { d3 8f [2] e1 ad [2] e7 98 [2] c9 98 [2] f6 84 }

  condition:
    any of them
}