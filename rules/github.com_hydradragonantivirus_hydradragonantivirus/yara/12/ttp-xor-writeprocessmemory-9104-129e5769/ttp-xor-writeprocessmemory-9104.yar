rule TTP_XOR_WriteProcessMemory_9104 {
  strings:
    $key_9104 = { c6 76 [2] f4 54 [2] f2 61 [2] dc 61 [2] e3 7d }

  condition:
    any of them
}